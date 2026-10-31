/* SPDX-License-Identifier: Apache-2.0 */
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.*;
import javax.net.ssl.*;

/** Finite independent Android HTTPS DoH test peer (TLS 1.2, ALPN http/1.1), never part of the Product runtime. */
public final class S323DoHPeer {
    private static String hex(byte[] bytes) {
        StringBuilder text = new StringBuilder(bytes.length * 2);
        for (byte value : bytes) text.append(String.format("%02x", value & 255));
        return text.toString();
    }
    private static byte[] unhex(String text) {
        if ((text.length() & 1) != 0 || text.length() > 131070) throw new IllegalArgumentException();
        byte[] bytes = new byte[text.length() / 2];
        for (int i = 0; i < bytes.length; ++i) bytes[i] = (byte) Integer.parseInt(text.substring(i * 2, i * 2 + 2), 16);
        return bytes;
    }
    private static String json(String text) {
        return text == null ? "null" : "\"" + text.replace("\\", "\\\\").replace("\"", "\\\"") + "\"";
    }
    public static void main(String[] args) {
        try { run(args); System.exit(0); }
        catch (Throwable error) { error.printStackTrace(); System.exit(1); }
    }
    private static byte[] head(String status, String extra, long length) {
        return ("HTTP/1.1 " + status + "\r\n" + extra + (length >= 0 ? "Content-Length: " + length + "\r\n" : "")
                + "Connection: close\r\n\r\n").getBytes(StandardCharsets.US_ASCII);
    }
    private static byte[] join(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length); System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }
    private static byte[] response(String mode, byte[] reply) throws IOException {
        String typed = "Content-Type: application/dns-message\r\n";
        if (mode.equals("ok")) return join(head("200 OK", typed, reply.length), reply);
        if (mode.startsWith("age=")) return join(head("200 OK", typed + "Age: " + mode.substring(4) + "\r\n", reply.length), reply);
        if (mode.equals("chunked")) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            out.write(head("200 OK", typed + "Transfer-Encoding: chunked\r\n", -1));
            for (int at = 0; at < reply.length; at += 24) {
                int n = Math.min(24, reply.length - at);
                out.write((Integer.toHexString(n) + "\r\n").getBytes(StandardCharsets.US_ASCII));
                out.write(reply, at, n); out.write("\r\n".getBytes(StandardCharsets.US_ASCII));
            }
            out.write("0\r\n\r\n".getBytes(StandardCharsets.US_ASCII));
            return out.toByteArray();
        }
        if (mode.equals("status404")) return join(head("404 Not Found", "Content-Type: text/plain\r\n", 9), "not found".getBytes(StandardCharsets.US_ASCII));
        if (mode.equals("redirect")) return head("301 Moved Permanently", "Location: https://redirect.invalid/dns-query\r\n", 0);
        if (mode.equals("wrongtype")) return join(head("200 OK", "Content-Type: application/json\r\n", reply.length), reply);
        throw new IllegalArgumentException(mode);
    }
    private static void run(String[] args) throws Exception {
        if (args.length != 3) throw new IllegalArgumentException();
        File directory = new File(args[0]);
        int port = Integer.parseInt(args[1]);
        int seconds = Integer.parseInt(args[2]);
        if (port < 1853 || port > 1854 || seconds < 1 || seconds > 900) throw new IllegalArgumentException();
        KeyStore keys = KeyStore.getInstance("PKCS12");
        try (InputStream input = new FileInputStream(new File(directory, "peer.p12"))) {
            keys.load(input, "s322-offline-fixture".toCharArray());
        }
        KeyManagerFactory managers = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        managers.init(keys, "s322-offline-fixture".toCharArray());
        SSLContext context = SSLContext.getInstance("TLSv1.2");
        context.init(managers.getKeyManagers(), null, new SecureRandom());
        int received = 0, connections = 0;
        long deadline = System.nanoTime() + seconds * 1_000_000_000L;
        try (SSLServerSocket listener = (SSLServerSocket) context.getServerSocketFactory()
                .createServerSocket(port, 8, InetAddress.getByName("127.0.0.1"))) {
            listener.setEnabledProtocols(new String[]{"TLSv1.2"});
            listener.setSoTimeout(250);
            System.out.println("{\"kind\":\"ready\",\"pid\":" + android.os.Process.myPid() + "}");
            while (!new File(directory, "stop").exists() && System.nanoTime() < deadline) {
                SSLSocket socket;
                try { socket = (SSLSocket) listener.accept(); }
                catch (SocketTimeoutException idle) { continue; }
                if (++connections > 128) throw new IOException("bounded connection capacity");
                try (SSLSocket stream = socket) {
                    stream.setSoTimeout(1500);
                    SSLParameters parameters = stream.getSSLParameters();
                    parameters.setApplicationProtocols(new String[]{"http/1.1"});
                    stream.setSSLParameters(parameters);
                    stream.startHandshake();
                    System.out.println("{\"kind\":\"authenticated\",\"connection\":" + connections
                            + ",\"version\":\"" + stream.getSession().getProtocol() + "\",\"alpn\":"
                            + json(stream.getApplicationProtocol()) + "}");
                    InputStream input = stream.getInputStream();
                    ByteArrayOutputStream headBytes = new ByteArrayOutputStream();
                    int window = 0;
                    while (window != 0x0d0a0d0a) {
                        int value = input.read();
                        if (value < 0 || headBytes.size() > 8192) throw new EOFException();
                        headBytes.write(value);
                        window = (window << 8) | value;
                    }
                    String[] lines = headBytes.toString("ISO-8859-1").split("\r\n");
                    String[] request = lines[0].split(" ");
                    String host = null, contentType = null, accept = null;
                    int length = -1;
                    for (int i = 1; i < lines.length; ++i) {
                        int colon = lines[i].indexOf(':');
                        if (colon < 0) continue;
                        String name = lines[i].substring(0, colon).toLowerCase(), value = lines[i].substring(colon + 1).trim();
                        if (name.equals("content-length")) length = Integer.parseInt(value);
                        else if (name.equals("host")) host = value;
                        else if (name.equals("content-type")) contentType = value;
                        else if (name.equals("accept")) accept = value;
                    }
                    if (length < 12 || length > 65535 || ++received > 128) throw new IOException("bounded DNS capacity");
                    byte[] query = new byte[length];
                    new DataInputStream(input).readFully(query);
                    System.out.println("{\"kind\":\"received\",\"request\":" + received
                            + ",\"connection\":" + connections + ",\"protocol\":\"tcp\",\"resolver\":[\"127.0.0.1\","
                            + port + "],\"request_hex\":\"" + hex(query) + "\",\"http\":{\"method\":" + json(request[0])
                            + ",\"target\":" + json(request[1]) + ",\"host\":" + json(host) + ",\"content_type\":"
                            + json(contentType) + ",\"accept\":" + json(accept) + ",\"alpn\":"
                            + json(stream.getApplicationProtocol()) + "}}");
                    MessageDigest digest = MessageDigest.getInstance("SHA-256");
                    digest.update(query, 2, query.length - 2);
                    File plan = new File(directory, "plan-" + hex(digest.digest()));
                    String text = new String(Files.readAllBytes(plan.toPath()), StandardCharsets.US_ASCII).trim();
                    if (!text.equals("DROP")) {
                        int space = text.indexOf(' ');
                        String mode = text.substring(0, space);
                        byte[] reply = unhex(text.substring(space + 1)); reply[0] = query[0]; reply[1] = query[1];
                        byte[] payload = response(mode, reply);
                        OutputStream output = stream.getOutputStream();
                        for (int at = 0; at < payload.length; at += 11) { output.write(payload, at, Math.min(11, payload.length - at)); output.flush(); }
                        System.out.println("{\"kind\":\"exchange\",\"request\":" + received
                                + ",\"reply_hex\":\"" + hex(reply) + "\",\"mode\":" + json(mode) + "}");
                    } else System.out.println("{\"kind\":\"cancelled\",\"request\":" + received + "}");
                } catch (SSLException | EOFException | SocketTimeoutException closed) {
                    System.out.println("{\"kind\":\"closed\",\"connection\":" + connections + "}");
                }
            }
        }
        System.out.println("{\"kind\":\"stopped\",\"received\":" + received + ",\"sockets\":0}");
        System.exit(0);
    }
}
