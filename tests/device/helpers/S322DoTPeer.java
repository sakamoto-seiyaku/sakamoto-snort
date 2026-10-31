/* SPDX-License-Identifier: Apache-2.0 */
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.*;
import javax.net.ssl.*;

/** Finite independent Android TLS test peer, never part of the Product runtime. */
public final class S322DoTPeer {
    private static String hex(byte[] bytes) {
        StringBuilder text = new StringBuilder(bytes.length * 2);
        for (byte value : bytes) text.append(String.format("%02x", value & 255));
        return text.toString();
    }
    private static byte[] unhex(String text) {
        if ((text.length() & 1) != 0 || text.length() > 131070) throw new IllegalArgumentException();
        byte[] bytes = new byte[text.length() / 2];
        for (int i = 0; i < bytes.length; ++i) {
            int value = Integer.parseInt(text.substring(i * 2, i * 2 + 2), 16);
            bytes[i] = (byte) value;
        }
        return bytes;
    }
    public static void main(String[] args) {
        try { run(args); System.exit(0); }
        catch (Throwable error) { error.printStackTrace(); System.exit(1); }
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
                    stream.startHandshake();
                    System.out.println("{\"kind\":\"authenticated\",\"connection\":" + connections
                            + ",\"version\":\"" + stream.getSession().getProtocol() + "\"}");
                    DataInputStream input = new DataInputStream(stream.getInputStream());
                    int length = input.readUnsignedShort();
                    if (length < 12 || ++received > 128) throw new IOException("bounded DNS capacity");
                    byte[] query = new byte[length]; input.readFully(query);
                    System.out.println("{\"kind\":\"received\",\"request\":" + received
                            + ",\"connection\":" + connections + ",\"protocol\":\"tcp\",\"resolver\":[\"127.0.0.1\","
                            + port + "],\"request_hex\":\"" + hex(query) + "\"}");
                    MessageDigest digest = MessageDigest.getInstance("SHA-256");
                    digest.update(query, 2, query.length - 2);
                    File plan = new File(directory, "plan-" + hex(digest.digest()));
                    String text = new String(Files.readAllBytes(plan.toPath()), StandardCharsets.US_ASCII).trim();
                    if (!text.equals("DROP")) {
                        byte[] reply = unhex(text); reply[0] = query[0]; reply[1] = query[1];
                        DataOutputStream output = new DataOutputStream(stream.getOutputStream());
                        output.writeShort(reply.length);
                        for (int at = 0; at < reply.length; at += 3) output.write(reply, at, Math.min(3, reply.length - at));
                        output.flush();
                        System.out.println("{\"kind\":\"exchange\",\"request\":" + received
                                + ",\"reply_hex\":\"" + hex(reply) + "\"}");
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
