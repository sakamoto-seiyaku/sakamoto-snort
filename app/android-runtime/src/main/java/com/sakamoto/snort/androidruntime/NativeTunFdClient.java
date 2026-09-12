package com.sakamoto.snort.androidruntime;

import android.net.LocalSocket;
import android.net.LocalSocketAddress;
import android.os.ParcelFileDescriptor;
import android.os.SystemClock;
import java.io.FileDescriptor;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/** Generation-scoped fd handoff only; packet bytes never use this channel. */
final class NativeTunFdClient {
    private NativeTunFdClient() {}

    static void attach(String runtimePath, long generation, int rawFd, int controlledUid)
            throws IOException {
        if (call(runtimePath, generation, 1, rawFd, controlledUid) != 0) {
            throw new IOException("native TUN handoff rejected");
        }
    }

    static boolean stop(String runtimePath, long generation) {
        long deadline = SystemClock.elapsedRealtime() + 8000;
        try {
            do {
                int result = call(runtimePath, generation, 2, -1, 0);
                if (result == 0) return true;
                if (result != 1) return false;
                Thread.sleep(50);
            } while (SystemClock.elapsedRealtime() < deadline);
        } catch (IOException error) {
            return false;
        } catch (InterruptedException error) {
            Thread.currentThread().interrupt();
        }
        return false;
    }

    static void attachUnknownIdentity(String runtimePath, long generation, int rawFd)
            throws IOException {
        if (call(runtimePath, generation, 4, rawFd, 0) != 0)
            throw new IOException("native TUN unknown-identity handoff rejected");
    }

    private static int call(String runtimePath, long generation, int command,
                            int rawFd, int uid) throws IOException {
        ParcelFileDescriptor descriptor = rawFd >= 0 ? ParcelFileDescriptor.adoptFd(rawFd) : null;
        try (LocalSocket socket = new LocalSocket(LocalSocket.SOCKET_SEQPACKET)) {
            socket.connect(new LocalSocketAddress(runtimePath + "/tun-control.sock",
                    LocalSocketAddress.Namespace.FILESYSTEM));
            socket.setSoTimeout(2500);
            if (descriptor != null) {
                socket.setFileDescriptorsForSend(new FileDescriptor[]{descriptor.getFileDescriptor()});
            }
            byte[] request = ByteBuffer.allocate(20).order(ByteOrder.BIG_ENDIAN)
                    .putInt(0x53323133).putInt(command).putLong(generation).putInt(uid).array();
            socket.getOutputStream().write(request);
            socket.setFileDescriptorsForSend(null);
            byte[] response = new byte[4];
            int n = socket.getInputStream().read(response);
            if (n != 4) throw new IOException("invalid native TUN control reply");
            return ByteBuffer.wrap(response).order(ByteOrder.BIG_ENDIAN).getInt();
        } finally {
            if (descriptor != null) descriptor.close();
        }
    }
}
