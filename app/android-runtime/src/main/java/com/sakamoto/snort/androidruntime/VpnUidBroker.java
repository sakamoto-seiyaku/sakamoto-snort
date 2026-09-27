package com.sakamoto.snort.androidruntime;

import android.net.ConnectivityManager;
import android.net.LocalSocket;
import android.net.LocalSocketAddress;
import android.net.VpnService;
import android.util.Log;
import java.io.FileDescriptor;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicBoolean;

/** Resolves only TCP/UDP tuple metadata for one native FlowOwner. Packet
 * buffers, decisions and the bounded UID cache stay in VPP. */
final class VpnUidBroker implements AutoCloseable {
    private static final String TAG = "SakamotoVpnUid";
    private static final int CONTROL_MAGIC = 0x53323133;
    private static final int MAGIC = 0x53323839;
    private final LocalSocket channel;
    private final ConnectivityManager connectivity;
    private final long generation;
    private final int ownerIndex;
    private final Runnable failure;
    private final Thread thread;
    private final AtomicBoolean failureDelivered = new AtomicBoolean();
    private volatile boolean stopping;

    private VpnUidBroker(LocalSocket channel, ConnectivityManager connectivity,
                         long generation, int ownerIndex, Runnable failure) {
        this.channel = channel;
        this.connectivity = connectivity;
        this.generation = generation;
        this.ownerIndex = ownerIndex;
        this.failure = failure;
        this.thread = new Thread(this::run, "sakamoto-vpn-uid-" + ownerIndex);
    }

    static VpnUidBroker start(VpnService service, String runtimePath,
                              long generation, int ownerIndex, Runnable failure)
            throws IOException {
        ConnectivityManager connectivity = service == null ? null
                : service.getSystemService(ConnectivityManager.class);
        if (connectivity == null || runtimePath == null || generation <= 0
                || ownerIndex < 0 || ownerIndex >= 2 || failure == null)
            throw new IOException("VPN UID broker configuration unavailable");
        LocalSocket socket = new LocalSocket(LocalSocket.SOCKET_SEQPACKET);
        boolean retained = false;
        try {
            socket.connect(new LocalSocketAddress(runtimePath + "/tun-control.sock",
                    LocalSocketAddress.Namespace.FILESYSTEM));
            socket.setSoTimeout(2500);
            if (socket.getPeerCredentials().getUid() != android.os.Process.myUid())
                throw new IOException("VPN UID broker peer UID mismatch");
            socket.getOutputStream().write(ByteBuffer.allocate(20).order(ByteOrder.BIG_ENDIAN)
                    .putInt(CONTROL_MAGIC).putInt(5).putLong(generation)
                    .putInt(ownerIndex).array());
            byte[] response = new byte[5];
            int length = socket.getInputStream().read(response);
            FileDescriptor[] unexpected = socket.getAncillaryFileDescriptors();
            closeUnexpected(unexpected);
            if (length != 4 || ByteBuffer.wrap(response).order(ByteOrder.BIG_ENDIAN)
                    .getInt() != 0 || (unexpected != null && unexpected.length != 0))
                throw new IOException("native VPN UID broker registration rejected");
            socket.setSoTimeout(0);
            VpnUidBroker broker = new VpnUidBroker(socket, connectivity,
                    generation, ownerIndex, failure);
            broker.thread.start();
            retained = true;
            return broker;
        } finally {
            if (!retained) socket.close();
        }
    }

    private void run() {
        boolean failed = false;
        try {
            while (!stopping) {
                byte[] bytes = new byte[65]; // Reject oversized SEQPACKET envelopes.
                int length = channel.getInputStream().read(bytes);
                FileDescriptor[] unexpected = channel.getAncillaryFileDescriptors();
                closeUnexpected(unexpected);
                if (length != 64 || (unexpected != null && unexpected.length != 0))
                    throw new IOException("invalid VPN UID request envelope");
                ByteBuffer request = ByteBuffer.wrap(bytes).order(ByteOrder.BIG_ENDIAN);
                int magic = request.getInt(), kind = request.getInt();
                long requestedGeneration = request.getLong(), requestId = request.getLong();
                int family = Byte.toUnsignedInt(request.get());
                int protocol = Byte.toUnsignedInt(request.get());
                int localPort = Short.toUnsignedInt(request.getShort());
                int remotePort = Short.toUnsignedInt(request.getShort());
                byte[] localBytes = new byte[16], remoteBytes = new byte[16];
                request.get(localBytes); request.get(remoteBytes);
                int reserved = Short.toUnsignedInt(request.getShort());
                if (magic != MAGIC || kind != 1 || requestedGeneration != generation
                        || requestId == 0 || (family != 4 && family != 6)
                        || (protocol != 6 && protocol != 17) || reserved != 0)
                    throw new IOException("invalid VPN UID request identity");
                InetAddress local = InetAddress.getByAddress(family == 4
                        ? Arrays.copyOfRange(localBytes, 12, 16) : localBytes);
                InetAddress remote = InetAddress.getByAddress(family == 4
                        ? Arrays.copyOfRange(remoteBytes, 12, 16) : remoteBytes);
                int uid;
                try {
                    uid = connectivity.getConnectionOwnerUid(protocol,
                            new InetSocketAddress(local, localPort),
                            new InetSocketAddress(remote, remotePort));
                } catch (SecurityException | IllegalArgumentException unavailable) {
                    // A lookup miss never invents the VPN app's UID or blocks a packet.
                    uid = android.os.Process.INVALID_UID;
                }
                if (stopping) return;
                channel.getOutputStream().write(ByteBuffer.allocate(28)
                        .order(ByteOrder.BIG_ENDIAN).putInt(MAGIC).putInt(2)
                        .putLong(generation).putLong(requestId).putInt(uid).array());
            }
        } catch (IOException | RuntimeException error) {
            failed = !stopping;
            if (failed) Log.e(TAG, "VPN UID broker channel failed owner=" + ownerIndex, error);
        } finally {
            closeChannel();
            if (failed && failureDelivered.compareAndSet(false, true)) failure.run();
        }
    }

    private static void closeUnexpected(FileDescriptor[] descriptors) {
        if (descriptors == null) return;
        for (FileDescriptor descriptor : descriptors) {
            if (descriptor == null) continue;
            try { android.system.Os.close(descriptor); }
            catch (android.system.ErrnoException error) {
                Log.e(TAG, "unexpected UID broker fd close failed", error);
            }
        }
    }

    void expectStop() { stopping = true; }

    private void closeChannel() {
        try { channel.shutdownInput(); } catch (IOException ignored) { }
        try { channel.shutdownOutput(); } catch (IOException ignored) { }
        try { channel.close(); } catch (IOException ignored) { }
    }

    boolean closeAndWait() {
        stopping = true;
        closeChannel();
        thread.interrupt();
        try { thread.join(1000); }
        catch (InterruptedException error) { Thread.currentThread().interrupt(); }
        return !thread.isAlive();
    }

    @Override public void close() { closeAndWait(); }
}
