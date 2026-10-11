package com.sakamoto.snort.androidruntime;

import android.net.LocalSocket;
import android.net.LocalSocketAddress;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;

/** Blocking receive of one native datagram at a time; no healthy-state polling. */
final class RootFaultChannel implements AutoCloseable {
    interface Listener {
        void onFault(RootFaultEvent event);
        void onFailure(IOException error);
    }

    private final LocalSocket socket;
    private final File path;
    private volatile boolean closed;

    private RootFaultChannel(LocalSocket socket, File path) {
        this.socket = socket;
        this.path = path;
    }

    static RootFaultChannel bind(File runtime) throws IOException {
        File path = new File(runtime, "root-fault.sock");
        if (path.exists() && !path.delete())
            throw new IOException("stale Root fault socket cannot be removed");
        LocalSocket socket = new LocalSocket(LocalSocket.SOCKET_DGRAM);
        try {
            socket.bind(new LocalSocketAddress(path.getAbsolutePath(),
                    LocalSocketAddress.Namespace.FILESYSTEM));
            return new RootFaultChannel(socket, path);
        } catch (IOException error) {
            socket.close();
            throw error;
        }
    }

    String path() { return path.getAbsolutePath(); }

    void start(Listener listener) {
        Thread reader = new Thread(() -> {
            try {
                InputStream input = socket.getInputStream();
                byte[] datagram = new byte[160];
                while (!closed) {
                    int length = input.read(datagram);
                    if (length < 0) throw new IOException("Root fault channel closed");
                    RootFaultEvent event = RootFaultEvent.parse(datagram, length);
                    if (event != null) listener.onFault(event);
                }
            } catch (IOException error) {
                if (!closed) listener.onFailure(error);
            }
        }, "sakamoto-root-fault-receiver");
        reader.start();
    }

    @Override public void close() {
        closed = true;
        try { socket.close(); } catch (IOException ignored) { }
        path.delete();
    }
}
