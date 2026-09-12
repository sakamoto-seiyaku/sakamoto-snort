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
    private long nextUnderlayEpoch;
    private UnderlayListener underlayListener;
    private boolean active;
    private boolean registered;
    private boolean debugMissing;

    private static final class Facts {
        int context;
        String interfaceName;
        long epoch;
        boolean eligible;
    }

    /** Binding incarnation, not a mutable default-network label or Android netId. */
    static final class Underlay {
        final Network network;
        final long epoch;
        final int context;
        Underlay(Network network, long epoch, int context) {
            this.network = network; this.epoch = epoch; this.context = context;
        }
    }

    interface UnderlayListener {
        void changed(Underlay selected, long invalidatedEpoch);
    }

    private final ConnectivityManager.NetworkCallback callback =
            new ConnectivityManager.NetworkCallback() {
        @Override public void onAvailable(Network network) {
            synchronized (PlatformNetworkSnapshots.this) {
                if (!active) return;
                networks.computeIfAbsent(network, ignored -> new Facts());
                notifyUnderlay(0);
                publish("available");
            }
        }
        @Override public void onCapabilitiesChanged(Network network,
                                                     NetworkCapabilities capabilities) {
            synchronized (PlatformNetworkSnapshots.this) {
                if (!active) return;
                Facts facts = networks.computeIfAbsent(network, ignored -> new Facts());
                long invalidated = updateCapabilities(facts, capabilities);
                notifyUnderlay(invalidated);
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
                Facts lost = networks.remove(network);
                notifyUnderlay(lost == null ? 0 : lost.epoch);
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
            // Seed before TUN admission. All later observations arrive through
            // this same generation-owned subscription, never per packet.
            for (Network network : manager.getAllNetworks()) {
                NetworkCapabilities capabilities = manager.getNetworkCapabilities(network);
                if (capabilities == null) continue;
                Facts facts = networks.computeIfAbsent(network, ignored -> new Facts());
                updateCapabilities(facts, capabilities);
                LinkProperties properties = manager.getLinkProperties(network);
                if (properties != null) facts.interfaceName = properties.getInterfaceName();
            }
            publish("initial_networks");
        } catch (RuntimeException error) {
            Log.w(TAG, "s232 subscription_unavailable " + error.getClass().getSimpleName());
        }
    }

    private long updateCapabilities(Facts facts, NetworkCapabilities capabilities) {
        int context = classify(capabilities);
        boolean eligible = !capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
                && (capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                    || context == 1 || context == 2 || context == 8);
        long invalidated = facts.eligible && !eligible ? facts.epoch : 0;
        if (!eligible) facts.epoch = 0;
        else if (!facts.eligible) {
            if (nextUnderlayEpoch == Long.MAX_VALUE)
                throw new IllegalStateException("underlay epoch exhausted");
            facts.epoch = ++nextUnderlayEpoch;
        }
        facts.eligible = eligible;
        facts.context = context;
        return invalidated;
    }

    synchronized Underlay currentUnderlay() {
        if (!active || !registered) return null;
        Underlay selected = null;
        int best = Integer.MAX_VALUE;
        for (Map.Entry<Network, Facts> entry : networks.entrySet()) {
            Facts facts = entry.getValue();
            if (!facts.eligible) continue;
            int rank = facts.context == 1 ? 0 : facts.context == 8 ? 1 : facts.context == 2 ? 2 : 3;
            if (rank < best || (rank == best && selected != null && facts.epoch < selected.epoch)) {
                best = rank;
                selected = new Underlay(entry.getKey(), facts.epoch, facts.context);
            }
        }
        return selected;
    }

    synchronized void setUnderlayListener(UnderlayListener listener) {
        if (!active || !registered || underlayListener != null || listener == null)
            throw new IllegalStateException("underlay subscription unavailable or already attached");
        underlayListener = listener;
        notifyUnderlay(0); // Atomic subscribe-and-current before first TUN input.
    }

    private void notifyUnderlay(long invalidatedEpoch) {
        if (underlayListener != null) underlayListener.changed(currentUnderlay(), invalidatedEpoch);
    }

    static int classify(NetworkCapabilities capabilities) {
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

    boolean closeAndWait() {
        synchronized (this) {
            boolean wasActive = active;
            active = false;
            underlayListener = null;
            if (registered) {
                try {
                    manager.unregisterNetworkCallback(callback);
                    registered = false;
                }
                catch (RuntimeException error) {
                    Log.w(TAG, "s232 unregister_failed " + error.getClass().getSimpleName());
                }
            }
            networks.clear();
            if (wasActive) publish("stop_unknown");
            thread.quitSafely();
        }
        boolean exited = VpnSocketBroker.awaitExit(thread, 2000);
        Log.i(TAG, "s232 event=subscription_stopped thread_alive=" + thread.isAlive());
        synchronized (this) { return exited && !registered; }
    }

    @Override public void close() {
        if (!closeAndWait())
            throw new IllegalStateException("network subscription remains live after close deadline");
    }
}
