package com.sakamoto.snort.androidruntime;

import android.net.ConnectivityManager;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.NetworkRequest;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.SystemClock;
import android.util.Log;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.HashMap;
import java.util.Map;
import java.util.TreeMap;

/** Generation-owned platform events; no packet-path platform queries. */
final class PlatformNetworkSnapshots implements AutoCloseable {
    private static final String TAG = "SakamotoNetwork";
    private static final int MAX_INTERFACES = 32;
    private final ConnectivityManager manager;
    private final RuntimeControlNative.Session session;
    private final java.util.function.IntConsumer publicationFailure;
    private final HandlerThread thread = new HandlerThread("sakamoto-network-events");
    private final Map<Network, Facts> networks = new HashMap<>();
    private long revision;
    private boolean active;
    private boolean registered;
    private boolean debugMissing;

    private static final class Facts {
        int context;
        String interfaceName;
    }

    private final ConnectivityManager.NetworkCallback callback =
            new ConnectivityManager.NetworkCallback() {
        @Override public void onAvailable(Network network) {
            synchronized (PlatformNetworkSnapshots.this) {
                if (!active) return;
                networks.put(network, new Facts());
                publish("available");
            }
        }
        @Override public void onCapabilitiesChanged(Network network,
                                                     NetworkCapabilities capabilities) {
            synchronized (PlatformNetworkSnapshots.this) {
                if (!active) return;
                Facts facts = networks.computeIfAbsent(network, ignored -> new Facts());
                facts.context = classify(capabilities);
                publish("capabilities");
            }
        }
        @Override public void onLinkPropertiesChanged(Network network,
                                                       LinkProperties properties) {
            synchronized (PlatformNetworkSnapshots.this) {
                if (!active) return;
                Facts facts = networks.computeIfAbsent(network, ignored -> new Facts());
                facts.interfaceName = properties.getInterfaceName();
                publish("link_properties");
            }
        }
        @Override public void onLost(Network network) {
            synchronized (PlatformNetworkSnapshots.this) {
                if (!active) return;
                networks.remove(network);
                publish("lost");
            }
        }
    };

    PlatformNetworkSnapshots(ConnectivityManager manager, RuntimeControlNative.Session session,
                             java.util.function.IntConsumer publicationFailure) {
        this.manager = manager;
        this.session = session;
        this.publicationFailure = publicationFailure;
    }

    synchronized void start() {
        if (active) throw new IllegalStateException("network subscription already active");
        active = true;
        thread.start();
        publish("start_unknown");
        if (manager == null) return;
        try {
            // Observe all visible networks, including VPN; never project the
            // default network onto unrelated packet interfaces.
            NetworkRequest request = new NetworkRequest.Builder().clearCapabilities().build();
            manager.registerNetworkCallback(request, callback, new Handler(thread.getLooper()));
            registered = true;
        } catch (RuntimeException error) {
            Log.w(TAG, "s232 subscription_unavailable " + error.getClass().getSimpleName());
        }
    }

    private static int classify(NetworkCapabilities capabilities) {
        if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) return 4;
        int context = 0;
        if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) context |= 1;
        if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) context |= 2;
        if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)) context |= 8;
        // Ambiguous or unsupported transport facts stay unavailable.
        return Integer.bitCount(context) == 1 ? context : 0;
    }

    private void publish(String event) {
        TreeMap<Integer, Integer> interfaces = new TreeMap<>();
        for (Facts facts : networks.values()) {
            if (facts.interfaceName == null || facts.context == 0) continue;
            try {
                NetworkInterface iface = NetworkInterface.getByName(facts.interfaceName);
                if (iface == null || iface.getIndex() <= 0) continue;
                int index = iface.getIndex();
                Integer prior = interfaces.get(index);
                interfaces.put(index, prior == null || prior == facts.context ? facts.context : 0);
            } catch (SocketException | SecurityException unavailable) {
                // Resolving a platform event may fail. It does not make a
                // packet wait, nor does it justify a guessed classification.
            }
        }
        interfaces.values().removeIf(context -> context == 0);
        if (debugMissing) interfaces.clear();
        if (interfaces.size() > MAX_INTERFACES) interfaces.clear();
        int[] pairs = new int[interfaces.size() * 2];
        int i = 0;
        for (Map.Entry<Integer, Integer> entry : interfaces.entrySet()) {
            pairs[i++] = entry.getKey();
            pairs[i++] = entry.getValue();
        }
        long timestamp = SystemClock.elapsedRealtimeNanos();
        int code = session.publishNetwork(++revision, timestamp, pairs);
        Log.i(TAG, "s232 event=" + event + " revision=" + revision
                + " event_elapsed_ns=" + timestamp + " interfaces=" + interfaces + " code=" + code);
        if (code != 0 && active) publicationFailure.accept(code);
    }

    synchronized void setDebugMissing(boolean missing) {
        if (!active) return;
        debugMissing = missing;
        publish(missing ? "controlled_missing" : "controlled_restore");
    }

    @Override public void close() {
        synchronized (this) {
            if (!active) return;
            active = false;
            if (registered) {
                try { manager.unregisterNetworkCallback(callback); }
                catch (RuntimeException error) {
                    Log.w(TAG, "s232 unregister_failed " + error.getClass().getSimpleName());
                }
                registered = false;
            }
            networks.clear();
            publish("stop_unknown");
            thread.quitSafely();
        }
        try {
            thread.join(2000);
        } catch (InterruptedException error) {
            Thread.currentThread().interrupt();
        }
        Log.i(TAG, "s232 event=subscription_stopped thread_alive=" + thread.isAlive());
    }
}
