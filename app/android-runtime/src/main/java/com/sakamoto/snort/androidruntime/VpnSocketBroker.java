package com.sakamoto.snort.androidruntime;

import android.net.LocalSocket;
import android.net.LocalSocketAddress;
import android.net.VpnService;
import android.os.ParcelFileDescriptor;
import android.system.ErrnoException;
import android.system.Os;
import android.util.Log;
import java.io.FileDescriptor;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/** Generation-scoped Android socket authorization. No packet bytes, HEV
 * scheduler or transport session execute in this process/thread. */
final class VpnSocketBroker implements AutoCloseable {
    private static final String TAG = "SakamotoSocketBroker";
    private static final int MAGIC = 0x53323337;
    // Android's public OsConstants omits these flags. Values are the Bionic
    // sys/socket.h ABI, verified against the pinned Android/NDK headers.
    private static final int MSG_DONTWAIT = 0x40, MSG_NOSIGNAL = 0x4000;
    private final LocalSocket channel;
    private final VpnService service;
    private final Object authorizationLock = new Object();
    private PlatformNetworkSnapshots.Underlay underlay;
    private final long generation;
    private final int ownerIndex;
    private final Runnable failure;
    private final boolean unknownContext;
    private final Thread thread;
    private volatile boolean stopping;
    private final java.util.concurrent.atomic.AtomicBoolean failureDelivered =
            new java.util.concurrent.atomic.AtomicBoolean();

    private VpnSocketBroker(LocalSocket channel, VpnService service,
                            long generation, int ownerIndex,
                            boolean unknownContext, Runnable failure) {
        this.channel = channel;
        this.service = service;
        this.generation = generation;
        this.ownerIndex = ownerIndex;
        this.failure = failure;
        this.unknownContext = unknownContext;
        this.thread = new Thread(this::run, "sakamoto-vpn-socket-broker-" + ownerIndex);
    }

    static VpnSocketBroker start(VpnService service, String runtimePath,
                                  long generation, int ownerIndex,
                                  boolean unknownContext, Runnable failure) throws IOException {
        if (service == null || generation <= 0 || failure == null
                || ownerIndex < 0 || ownerIndex >= 2)
            throw new IOException("socket broker configuration missing");
        LocalSocket socket = new LocalSocket(LocalSocket.SOCKET_SEQPACKET);
        boolean retained = false;
        try {
            socket.connect(new LocalSocketAddress(runtimePath + "/tun-control.sock",
                    LocalSocketAddress.Namespace.FILESYSTEM));
            socket.setSoTimeout(2500);
            if (socket.getPeerCredentials().getUid() != android.os.Process.myUid())
                throw new IOException("socket broker peer UID mismatch");
            socket.getOutputStream().write(ByteBuffer.allocate(20).order(ByteOrder.BIG_ENDIAN)
                    .putInt(0x53323133).putInt(3).putLong(generation).putInt(ownerIndex).array());
            byte[] response = new byte[5];
            int length = socket.getInputStream().read(response);
            FileDescriptor[] unexpected = socket.getAncillaryFileDescriptors();
            closeReceived(unexpected);
            if (length != 4 || (unexpected != null && unexpected.length != 0)
                    || ByteBuffer.wrap(response).order(ByteOrder.BIG_ENDIAN).getInt() != 0)
                throw new IOException("native socket broker registration rejected");
            socket.setSoTimeout(0); // Only this control thread waits; close wakes it.
            VpnSocketBroker broker = new VpnSocketBroker(socket, service,
                    generation, ownerIndex, unknownContext, failure);
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
                byte[] request = new byte[33]; // Detect oversized seqpacket messages.
                int length = channel.getInputStream().read(request);
                FileDescriptor[] received = channel.getAncillaryFileDescriptors();
                try {
                    if (length < 0) throw new IOException("native broker channel closed");
                    if (length != 32 || received == null || received.length != 1)
                        throw new IOException("invalid socket broker envelope");
                    ByteBuffer message = ByteBuffer.wrap(request).order(ByteOrder.BIG_ENDIAN);
                    int magic = message.getInt(), operation = message.getInt();
                    long requestGeneration = message.getLong(), session = message.getLong();
                    int owner = message.getInt(), diagnostic = message.getInt();
                    if (magic != MAGIC || operation != 1 || requestGeneration != generation
                            || session == 0 || owner != ownerIndex
                            || (diagnostic != 0 && diagnostic != 2 && diagnostic != 3)
                            || (diagnostic != 0 && (service.getApplicationInfo().flags
                                & android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE) == 0))
                        throw new IOException("invalid socket broker identity");
                    synchronized (authorizationLock) {
                        PlatformNetworkSnapshots.Underlay binding = underlay;
                        long epoch = binding == null ? 0 : binding.epoch;
                        int flags = 0, error = binding == null ? 5 : 4, context = 0;
                        if (!stopping && binding != null) {
                            // dup supplies the public integer accessor required by protect(int).
                            // Both this reference and the received SCM_RIGHTS reference close here.
                            try (ParcelFileDescriptor descriptor = ParcelFileDescriptor.dup(received[0])) {
                                if (diagnostic == 2) {
                                    // Actual platform failure on an invalid descriptor; the real
                                    // socket never becomes eligible for native connect/send.
                                    error = service.protect(-1) ? 4 : 2;
                                } else if (!service.protect(descriptor.getFd())) error = 2;
                                else {
                                    flags |= 1;
                                    try {
                                        if (diagnostic == 3) {
                                            binding.network.bindSocket(new FileDescriptor());
                                            error = 4; // Unexpected invalid-fd success is not a bind failure.
                                        } else {
                                            binding.network.bindSocket(descriptor.getFileDescriptor());
                                            flags |= 2;
                                            error = 0;
                                        }
                                    } catch (IOException | RuntimeException bindFailure) {
                                        error = 3;
                                    }
                                }
                            } catch (IOException | RuntimeException authorizationFailure) {
                                // A partial authorization never permits native connect/send.
                                error = 4;
                            }
                        }
                        if (error != 0) flags &= ~2;
                        if (error == 0 && !unknownContext) {
                            context = binding.context;
                            if (context != 0) flags |= 4;
                        }
                        Log.i(TAG, "s237 broker generation=" + generation + " session=" + session
                                + " owner=" + owner + " flags=" + flags + " error=" + error
                                + " epoch=" + epoch + " context=" + context + " diagnostic=" + diagnostic);
                        // Close received ownership before reporting completion; no descriptor
                        // remains in Java after the native session becomes eligible to connect.
                        closeReceived(received);
                        received = null;
                        sendControl(ByteBuffer.allocate(48).order(ByteOrder.BIG_ENDIAN)
                                .putInt(MAGIC).putInt(2).putLong(generation).putLong(session)
                                .putInt(owner).putInt(error).putLong(epoch).putInt(context).putInt(flags).array());
                    }
                } finally {
                    closeReceived(received);
                }
            }
        } catch (IOException | RuntimeException error) {
            failed = !stopping;
            if (failed) Log.e(TAG, "s237 broker failed", error);
        } finally {
            closeChannel();
            if (failed) reportFailure();
        }
    }

    void updateUnderlay(PlatformNetworkSnapshots.Underlay selected, long invalidatedEpoch) {
        try {
            synchronized (authorizationLock) {
                if (stopping) return;
                underlay = selected;
                if (invalidatedEpoch != 0) {
                    sendControl(ByteBuffer.allocate(48).order(ByteOrder.BIG_ENDIAN)
                            .putInt(MAGIC).putInt(3).putLong(generation).putLong(0)
                            .putInt(ownerIndex).putInt(0).putLong(invalidatedEpoch)
                            .putInt(0).putInt(0).array());
                }
                Log.i(TAG, "s243 underlay generation=" + generation + " owner=" + ownerIndex
                        + " invalidated=" + invalidatedEpoch
                        + " selected=" + (selected == null ? 0 : selected.epoch)
                        + " network=" + (selected == null ? 0 : selected.network.getNetworkHandle()));
            }
        } catch (IOException | RuntimeException error) {
            Log.e(TAG, "s243 underlay control failed", error);
            closeChannel();
            reportFailure();
        }
    }

    private void sendControl(byte[] data) throws IOException {
        // SEQPACKET preserves the order of authorization and invalidation.
        // A full channel is a visible infrastructure failure, never a silent
        // lost invalidation or a blocking network-callback queue.
        try {
            int sent = Os.sendto(channel.getFileDescriptor(), data, 0, data.length,
                    MSG_DONTWAIT | MSG_NOSIGNAL, null, 0);
            if (sent != data.length) throw new IOException("short broker control write");
        } catch (ErrnoException error) {
            throw new IOException("broker control send failed", error);
        }
    }

    private void reportFailure() {
        if (!stopping && failureDelivered.compareAndSet(false, true)) failure.run();
    }

    private static void closeReceived(FileDescriptor[] descriptors) {
        if (descriptors == null) return;
        for (FileDescriptor descriptor : descriptors) {
            if (descriptor == null) continue;
            try { Os.close(descriptor); }
            catch (ErrnoException error) { Log.e(TAG, "received fd close failed", error); }
        }
    }

    void expectStop() { stopping = true; }

    private void closeChannel() {
        // LocalSocket.close() alone does not cancel a concurrent blocking
        // recvmsg: that syscall retains the socket's file reference. Shutdown
        // wakes both read/write first, including the broker-failure path.
        try { channel.shutdownInput(); } catch (IOException ignored) { }
        try { channel.shutdownOutput(); } catch (IOException ignored) { }
        try { channel.close(); } catch (IOException ignored) { }
    }

    // Called only by the debuggable generation-owned lifecycle fault seam.
    // Do not set stopping: both peers must observe a genuine channel failure.
    void failChannelForTest() { closeChannel(); }

    static boolean awaitExit(Thread worker, long timeoutMillis) {
        if (Thread.currentThread() == worker || timeoutMillis <= 0) return false;
        try { worker.join(timeoutMillis); }
        catch (InterruptedException error) { Thread.currentThread().interrupt(); }
        return !worker.isAlive();
    }

    boolean closeAndWait() {
        stopping = true;
        closeChannel();
        thread.interrupt();
        return awaitExit(thread, 1000);
    }

    @Override public void close() {
        if (!closeAndWait()) throw new IllegalStateException("broker thread remains live after close deadline");
    }
}
