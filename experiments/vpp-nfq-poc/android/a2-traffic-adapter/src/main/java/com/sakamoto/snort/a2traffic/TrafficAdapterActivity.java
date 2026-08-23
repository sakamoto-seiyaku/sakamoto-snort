package com.sakamoto.snort.a2traffic;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.net.ConnectivityManager;
import android.net.LinkAddress;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.os.Bundle;
import android.os.Process;
import android.os.SystemClock;
import android.util.Log;
import android.widget.TextView;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicLong;

/**
 * POC-only deterministic real-App traffic generator for S139 A2-1.
 *
 * <p>The source is built twice with different manifest application IDs. Each
 * invocation emits one fixed tuple operation. A repeat count deliberately
 * reuses the same tuple (including the source port) so an owner resolver can
 * observe a miss, completion, and cache hit without an ephemeral-port change.
 * This class makes no external-connect or reply claim.</p>
 */
public final class TrafficAdapterActivity extends Activity {
    private static final String TAG = "S139A2Traffic";
    private static final String ACTION_EMIT =
            "com.sakamoto.snort.a2traffic.EMIT";
    private static final String EXTRA_MATRIX = "a2Matrix";
    private static final String EXTRA_STAGE_ID = "a2MatrixStageId";
    private static final String EXTRA_FAMILY = "a2MatrixFamily";
    private static final String EXTRA_PROTOCOL = "a2MatrixProtocol";
    private static final String EXTRA_SOURCE_PORT = "a2MatrixSourcePort";
    private static final String EXTRA_DESTINATION_HOST =
            "a2MatrixDestinationHost";
    private static final String EXTRA_DESTINATION_PORT =
            "a2MatrixDestinationPort";
    private static final String EXTRA_TIMEOUT_MILLIS =
            "a2MatrixTimeoutMillis";
    private static final String EXTRA_REPEAT = "a2MatrixRepeat";
    private static final String EVIDENCE_PATH = "debug/a2-1-runtime.jsonl";
    private static final String SCHEMA = "s139-a2-1-runtime/v1";
    private static final int DEFAULT_TIMEOUT_MILLIS = 1200;
    private static final int MIN_TCP_TIMEOUT_MILLIS = 100;
    private static final int MAX_REPEAT = 16;
    private static final long VPN_WAIT_MILLIS = 10000L;
    private static final AtomicLong SEQUENCE = new AtomicLong(0L);
    private static final Object EVIDENCE_LOCK = new Object();

    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        TextView view = new TextView(this);
        view.setText("S139 A2-1 traffic adapter");
        setContentView(view);
        handleIntent(getIntent());
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        setIntent(intent);
        handleIntent(intent);
    }

    private void handleIntent(Intent intent) {
        if (intent == null || !isEmitCommand(intent)) {
            return;
        }
        final Command command = Command.from(intent);
        Thread worker = new Thread(() -> {
            for (int index = 1; index <= command.repeat; index++) {
                runOperation(command, index, command.repeat);
            }
        }, "s139-a2-1-traffic");
        worker.start();
    }

    private boolean isEmitCommand(Intent intent) {
        return ACTION_EMIT.equals(intent.getAction())
                || intent.getBooleanExtra(EXTRA_MATRIX, false);
    }

    private void runOperation(Command command, int repeatIndex, int repeatCount) {
        long sequence = SEQUENCE.incrementAndGet();
        int uid = Process.myUid();
        String packageName = getPackageName();
        ProbeResult result;
        if (!command.validationError.isEmpty()) {
            result = ProbeResult.invalid(command.validationError,
                    command.destinationHost);
        } else {
            result = performProbe(command);
        }

        long monotonicNs = SystemClock.elapsedRealtimeNanos();
        JSONObject record = operationRecord(command, result, sequence,
                monotonicNs, repeatIndex, repeatCount, packageName, uid);
        appendRecord(record);
        setStatus(command.stageId, result.outcome);
    }

    private void setStatus(final String stageId, final String outcome) {
        runOnUiThread(() -> {
            TextView view = new TextView(this);
            view.setText("A2-1 " + stageId + " " + outcome);
            setContentView(view);
        });
    }

    private ProbeResult performProbe(Command command) {
        Network network = findVpnNetwork();
        if (network == null) {
            return ProbeResult.unavailable(command.destinationHost,
                    "no_active_transport_vpn");
        }
        long networkHandle = network.getNetworkHandle();
        InetAddress destination;
        try {
            destination = resolveDestination(command.destinationHost,
                    command.family);
        } catch (IOException error) {
            return ProbeResult.notAttempted(networkHandle,
                    command.destinationHost, "destination_resolution_failed",
                    boundedError(error));
        }

        if ("udp".equals(command.protocol)) {
            return performUdp(network, networkHandle, command, destination);
        }
        return performTcp(network, networkHandle, command, destination);
    }

    private ProbeResult performUdp(Network network, long networkHandle,
                                   Command command, InetAddress destination) {
        DatagramSocket socket = null;
        String bindResult = "not_attempted";
        boolean tupleAttempted = false;
        try {
            socket = new DatagramSocket(null);
            socket.setReuseAddress(true);
            socket.bind(new InetSocketAddress(wildcard(command.family),
                    command.sourcePort));
            try {
                // This is the transport-admission boundary for this real App
                // socket; process-wide binding is intentionally not used.
                network.bindSocket(socket);
                bindResult = "bound";
            } catch (IOException | RuntimeException error) {
                bindResult = "failed";
                return ProbeResult.failure(networkHandle, bindResult,
                        localAddress(socket, network, command.family),
                        destination.getHostAddress(), "vpn_bind_failed", false,
                        boundedError(error));
            }
            tupleAttempted = true;
            socket.connect(destination, command.destinationPort);
            String local = localAddress(socket, network, command.family);
            byte[] payload = ("s139-a2-1|" + command.family + "|udp")
                    .getBytes(StandardCharsets.UTF_8);
            socket.send(new DatagramPacket(payload, payload.length));
            // timeoutMillis is a post-send observation delay.  Keep the socket
            // alive when the native owner lookup is asynchronous; the runner
            // captures the durable record after the native family gates.
            if (command.timeoutMillis > 0) {
                SystemClock.sleep(Math.min(command.timeoutMillis, 3000));
            }
            return ProbeResult.success(networkHandle, bindResult, local,
                    destination.getHostAddress(), "udp_datagram_sent",
                    tupleAttempted, "");
        } catch (IOException | RuntimeException error) {
            String local = socket == null ? ""
                    : localAddress(socket, network, command.family);
            return ProbeResult.failure(networkHandle, bindResult, local,
                    destination.getHostAddress(), "udp_datagram_failed",
                    tupleAttempted, boundedError(error));
        } finally {
            if (socket != null) {
                socket.close();
            }
        }
    }

    private ProbeResult performTcp(Network network, long networkHandle,
                                   Command command, InetAddress destination) {
        Socket socket = null;
        String bindResult = "not_attempted";
        boolean tupleAttempted = false;
        try {
            socket = new Socket();
            socket.setReuseAddress(true);
            socket.bind(new InetSocketAddress(wildcard(command.family),
                    command.sourcePort));
            try {
                // Bind before connect so the tuple has a fixed source port and
                // is explicitly admitted by the selected TRANSPORT_VPN.
                network.bindSocket(socket);
                bindResult = "bound";
            } catch (IOException | RuntimeException error) {
                bindResult = "failed";
                return ProbeResult.failure(networkHandle, bindResult,
                        localAddress(socket, network, command.family),
                        destination.getHostAddress(), "vpn_bind_failed", false,
                        boundedError(error));
            }
            tupleAttempted = true;
            socket.connect(new InetSocketAddress(destination,
                    command.destinationPort), command.timeoutMillis);
            String local = localAddress(socket, network, command.family);
            return ProbeResult.success(networkHandle, bindResult, local,
                    destination.getHostAddress(), "tcp_connect_succeeded",
                    tupleAttempted, "");
        } catch (SocketTimeoutException error) {
            String local = socket == null ? ""
                    : localAddress(socket, network, command.family);
            return ProbeResult.failure(networkHandle, bindResult, local,
                    destination.getHostAddress(), "tcp_connect_timeout",
                    tupleAttempted, boundedError(error));
        } catch (IOException | RuntimeException error) {
            String local = socket == null ? ""
                    : localAddress(socket, network, command.family);
            return ProbeResult.failure(networkHandle, bindResult, local,
                    destination.getHostAddress(), "tcp_connect_failed",
                    tupleAttempted, boundedError(error));
        } finally {
            if (socket != null) {
                try {
                    socket.close();
                } catch (IOException ignored) {
                    // Do not replace the operation result with cleanup noise.
                }
            }
        }
    }

    private Network findVpnNetwork() {
        ConnectivityManager manager = (ConnectivityManager)
                getSystemService(Context.CONNECTIVITY_SERVICE);
        if (manager == null) {
            return null;
        }
        long deadline = SystemClock.elapsedRealtime() + VPN_WAIT_MILLIS;
        while (SystemClock.elapsedRealtime() <= deadline) {
            Network selected = null;
            for (Network network : manager.getAllNetworks()) {
                NetworkCapabilities caps = manager.getNetworkCapabilities(network);
                if (caps == null || !caps.hasTransport(
                        NetworkCapabilities.TRANSPORT_VPN)) {
                    continue;
                }
                if (selected == null || network.getNetworkHandle()
                        < selected.getNetworkHandle()) {
                    selected = network;
                }
            }
            if (selected != null) {
                return selected;
            }
            SystemClock.sleep(100L);
        }
        return null;
    }

    private InetAddress resolveDestination(String host, String family)
            throws IOException {
        String normalizedHost = stripIpv6Brackets(host);
        InetAddress[] addresses = InetAddress.getAllByName(normalizedHost);
        for (InetAddress address : addresses) {
            if ("ip4".equals(family) && address instanceof Inet4Address) {
                return address;
            }
            if ("ip6".equals(family) && address instanceof Inet6Address) {
                return address;
            }
        }
        throw new IOException("no " + family + " destination address for "
                + host);
    }

    private InetAddress wildcard(String family) throws IOException {
        return InetAddress.getByName("ip6".equals(family) ? "::" : "0.0.0.0");
    }

    private String localAddress(Object socket, Network network, String family) {
        InetAddress address = null;
        if (socket instanceof Socket) {
            address = ((Socket) socket).getLocalAddress();
        } else if (socket instanceof DatagramSocket) {
            address = ((DatagramSocket) socket).getLocalAddress();
        }
        if (usableAddress(address, family)) {
            return address.getHostAddress();
        }
        // A failed connect can leave a wildcard local endpoint. Retain the
        // active VPN address as diagnostic evidence, but never call it a
        // successful connect/send outcome.
        ConnectivityManager manager = (ConnectivityManager)
                getSystemService(Context.CONNECTIVITY_SERVICE);
        if (manager != null) {
            LinkProperties properties = manager.getLinkProperties(network);
            if (properties != null) {
                for (LinkAddress linkAddress : properties.getLinkAddresses()) {
                    InetAddress candidate = linkAddress.getAddress();
                    if (usableAddress(candidate, family)) {
                        return candidate.getHostAddress();
                    }
                }
            }
        }
        return address == null ? "" : address.getHostAddress();
    }

    private boolean usableAddress(InetAddress address, String family) {
        if (address == null || address.isAnyLocalAddress()
                || address.isLoopbackAddress()) {
            return false;
        }
        return ("ip4".equals(family) && address instanceof Inet4Address)
                || ("ip6".equals(family) && address instanceof Inet6Address);
    }

    private JSONObject operationRecord(Command command, ProbeResult result,
                                       long sequence, long monotonicNs,
                                       int repeatIndex, int repeatCount,
                                       String packageName, int uid) {
        SafeJson record = new SafeJson();
        record.putSafe("schema", SCHEMA);
        record.putSafe("cell_id", "A2-1");
        record.putSafe("stage_id", command.stageId);
        record.putSafe("sequence", sequence);
        record.putSafe("monotonic_ns", monotonicNs);
        record.putSafe("generation", 1);
        record.putSafe("network_epoch", 1);
        record.putSafe("app_epoch", 1);
        record.putSafe("event", "TRAFFIC_RESULT");
        record.putSafe("app_package", packageName);
        record.putSafe("package", packageName);
        record.putSafe("uid", uid);
        record.putSafe("process_uid", uid);
        record.putSafe("family", command.family);
        record.putSafe("protocol", command.protocol);
        record.putSafe("source_address", result.localAddress);
        record.putSafe("source_port", command.sourcePort);
        record.putSafe("destination_address", result.destinationAddress);
        record.putSafe("destination_host", command.destinationHost);
        record.putSafe("destination_port", command.destinationPort);
        record.putSafe("bind_result", result.bindResult);
        record.putSafe("vpn_network_handle", result.networkHandle);
        record.putSafe("actual_local_address", result.localAddress);
        record.putSafe("send_connect_outcome", result.outcome);
        record.putSafe("tuple_attempted", result.tupleAttempted);
        record.putSafe("error", result.error);
        record.putSafe("repeat_index", repeatIndex);
        record.putSafe("repeat_count", repeatCount);
        record.putSafe("flow_id", command.stageId + "|" + command.family
                + "|" + command.protocol + "|" + command.sourcePort);
        record.putSafe("token", command.stageId + "-" + sequence);
        record.putSafe("canonical_key", command.family + "|"
                + command.protocol + "|" + command.sourcePort + "|"
                + formatEndpoint(result.destinationAddress, command.family)
                + ":" + command.destinationPort);

        SafeJson source = new SafeJson();
        source.putSafe("address", result.localAddress);
        source.putSafe("port", command.sourcePort);
        SafeJson destination = new SafeJson();
        destination.putSafe("address", result.destinationAddress);
        destination.putSafe("port", command.destinationPort);
        record.putSafe("source_tuple", source);
        record.putSafe("destination_tuple", destination);

        // Keep the first POC readers source-compatible while the revised
        // envelope uses snake_case names above.
        record.putSafe("cellId", "A2-1");
        record.putSafe("stageId", command.stageId);
        record.putSafe("monotonicNs", monotonicNs);
        record.putSafe("appPackage", packageName);
        record.putSafe("sourcePort", command.sourcePort);
        record.putSafe("destinationHost", command.destinationHost);
        record.putSafe("destinationPort", command.destinationPort);
        record.putSafe("vpnBindResult", result.bindResult);
        record.putSafe("vpnNetworkHandle", result.networkHandle);
        record.putSafe("localAddress", result.localAddress);
        record.putSafe("result", result.outcome);
        return record;
    }

    private void appendRecord(JSONObject record) {
        File file = new File(getFilesDir(), EVIDENCE_PATH);
        File parent = file.getParentFile();
        synchronized (EVIDENCE_LOCK) {
            try {
                if (parent != null && !parent.exists() && !parent.mkdirs()) {
                    throw new IOException("unable to create " + parent);
                }
                try (FileOutputStream output = new FileOutputStream(file, true)) {
                    output.write(record.toString().getBytes(StandardCharsets.UTF_8));
                    output.write('\n');
                    output.getFD().sync();
                }
            } catch (IOException error) {
                Log.e(TAG, "unable to durably append A2-1 JSONL", error);
            }
        }
    }

    private static String formatEndpoint(String address, String family) {
        if (address == null || address.isEmpty()) {
            return "";
        }
        return "ip6".equals(family) ? "[" + address + "]" : address;
    }

    private static String stripIpv6Brackets(String host) {
        if (host != null && host.length() > 1 && host.charAt(0) == '['
                && host.charAt(host.length() - 1) == ']') {
            return host.substring(1, host.length() - 1);
        }
        return host;
    }

    private static String stringExtra(Intent intent, String primary,
                                      String alias, String fallback) {
        String value = intent.getStringExtra(primary);
        if (value == null && alias != null) {
            value = intent.getStringExtra(alias);
        }
        return value == null || value.trim().isEmpty() ? fallback : value.trim();
    }

    private static int intExtra(Intent intent, String primary, String alias,
                                int fallback) {
        if (intent.hasExtra(primary)) {
            return intent.getIntExtra(primary, fallback);
        }
        if (alias != null && intent.hasExtra(alias)) {
            return intent.getIntExtra(alias, fallback);
        }
        return fallback;
    }

    private static String boundedError(Throwable error) {
        String message = error.getMessage();
        if (message == null || message.isEmpty()) {
            return error.getClass().getSimpleName();
        }
        return message.length() <= 240 ? message : message.substring(0, 240);
    }

    private static final class Command {
        final String stageId;
        final String family;
        final String protocol;
        final int sourcePort;
        final String destinationHost;
        final int destinationPort;
        final int timeoutMillis;
        final int repeat;
        final String validationError;

        private Command(String stageId, String family, String protocol,
                        int sourcePort, String destinationHost,
                        int destinationPort, int timeoutMillis, int repeat,
                        String validationError) {
            this.stageId = stageId;
            this.family = family;
            this.protocol = protocol;
            this.sourcePort = sourcePort;
            this.destinationHost = destinationHost;
            this.destinationPort = destinationPort;
            this.timeoutMillis = timeoutMillis;
            this.repeat = repeat;
            this.validationError = validationError;
        }

        static Command from(Intent intent) {
            String stageId = stringExtra(intent, EXTRA_STAGE_ID, "stageId",
                    "A2-1");
            String rawFamily = stringExtra(intent, EXTRA_FAMILY, "family",
                    "ip4");
            String rawProtocol = stringExtra(intent, EXTRA_PROTOCOL, "protocol",
                    "udp");
            String family = normalizeFamily(rawFamily);
            String protocol = normalizeProtocol(rawProtocol);
            int defaultSource = defaultSourcePort(family, protocol);
            int defaultDestination = defaultDestinationPort(protocol);
            int sourcePort = intExtra(intent, EXTRA_SOURCE_PORT, "sourcePort",
                    defaultSource);
            int destinationPort = intExtra(intent, EXTRA_DESTINATION_PORT,
                    "destinationPort", defaultDestination);
            String destinationHost = stringExtra(intent, EXTRA_DESTINATION_HOST,
                    "destinationHost", defaultDestinationHost(family));
            int timeout = intExtra(intent, EXTRA_TIMEOUT_MILLIS,
                    "timeoutMillis", DEFAULT_TIMEOUT_MILLIS);
            int repeat = intExtra(intent, EXTRA_REPEAT, "repeat", 1);
            String error = "";
            if (family == null) {
                error = "family must be ip4 or ip6";
            } else if (protocol == null) {
                error = "protocol must be tcp or udp";
            } else if (!validPort(sourcePort) || !validPort(destinationPort)) {
                error = "source and destination ports must be 1..65535";
            } else if (repeat < 1 || repeat > MAX_REPEAT) {
                error = "repeat must be 1.." + MAX_REPEAT;
            }
            if (timeout < 0 || timeout > 5000) {
                error = "timeoutMillis must be 0..5000";
                timeout = Math.max(0, Math.min(timeout, 5000));
            } else if ("tcp".equals(protocol) && timeout < MIN_TCP_TIMEOUT_MILLIS) {
                // java.net.Socket treats connect timeout=0 as unbounded.  Keep
                // the zero-delay mode specific to UDP so a malformed TCP
                // command cannot turn into an unbounded probe.
                error = "TCP timeoutMillis must be 100..5000";
                timeout = MIN_TCP_TIMEOUT_MILLIS;
            }
            return new Command(stageId, family == null ? "" : family,
                    protocol == null ? "" : protocol, sourcePort,
                    stripIpv6Brackets(destinationHost), destinationPort, timeout,
                    repeat < 1 || repeat > MAX_REPEAT ? 1 : repeat, error);
        }

        private static boolean validPort(int port) {
            return port >= 1 && port <= 65535;
        }

        private static String normalizeFamily(String value) {
            if ("ip4".equalsIgnoreCase(value)
                    || "ipv4".equalsIgnoreCase(value)
                    || "4".equals(value)) {
                return "ip4";
            }
            if ("ip6".equalsIgnoreCase(value)
                    || "ipv6".equalsIgnoreCase(value)
                    || "6".equals(value)) {
                return "ip6";
            }
            return null;
        }

        private static String normalizeProtocol(String value) {
            if ("tcp".equalsIgnoreCase(value)) {
                return "tcp";
            }
            if ("udp".equalsIgnoreCase(value)) {
                return "udp";
            }
            return null;
        }

        private static int defaultSourcePort(String family, String protocol) {
            if ("ip4".equals(family) && "tcp".equals(protocol)) {
                return 45621;
            }
            if ("ip6".equals(family) && "tcp".equals(protocol)) {
                return 45622;
            }
            if ("ip6".equals(family) && "udp".equals(protocol)) {
                return 45623;
            }
            return 45624;
        }

        private static int defaultDestinationPort(String protocol) {
            return "tcp".equals(protocol) ? 443 : 53;
        }

        private static String defaultDestinationHost(String family) {
            return "ip6".equals(family)
                    ? "2606:4700:4700::1111" : "1.1.1.1";
        }
    }

    private static final class ProbeResult {
        final String bindResult;
        final long networkHandle;
        final String localAddress;
        final String destinationAddress;
        final String outcome;
        final boolean tupleAttempted;
        final String error;

        private ProbeResult(String bindResult, long networkHandle,
                            String localAddress, String destinationAddress,
                            String outcome, boolean tupleAttempted,
                            String error) {
            this.bindResult = bindResult;
            this.networkHandle = networkHandle;
            this.localAddress = localAddress == null ? "" : localAddress;
            this.destinationAddress = destinationAddress == null
                    ? "" : destinationAddress;
            this.outcome = outcome;
            this.tupleAttempted = tupleAttempted;
            this.error = error == null ? "" : error;
        }

        static ProbeResult success(long handle, String bindResult, String local,
                                   String destination, String outcome,
                                   boolean attempted, String error) {
            return new ProbeResult(bindResult, handle, local, destination,
                    outcome, attempted, error);
        }

        static ProbeResult failure(long handle, String bindResult, String local,
                                   String destination, String outcome,
                                   boolean attempted, String error) {
            return new ProbeResult(bindResult, handle, local, destination,
                    outcome, attempted, error);
        }

        static ProbeResult unavailable(String destination, String error) {
            return new ProbeResult("unavailable", -1L, "", destination,
                    "vpn_unavailable", false, error);
        }

        static ProbeResult notAttempted(long handle, String destination,
                                        String outcome, String error) {
            return new ProbeResult("not_attempted", handle, "", destination,
                    outcome, false, error);
        }

        static ProbeResult invalid(String error, String destination) {
            return new ProbeResult("not_attempted", -1L, "", destination,
                    "invalid_command", false, error);
        }
    }

    /** Concise JSON writes while retaining checked JSONException handling. */
    private static final class SafeJson extends JSONObject {
        SafeJson putSafe(String key, Object value) {
            try {
                put(key, value);
            } catch (JSONException ignored) {
                // All keys are constants and values are non-null here.
            }
            return this;
        }
    }
}
