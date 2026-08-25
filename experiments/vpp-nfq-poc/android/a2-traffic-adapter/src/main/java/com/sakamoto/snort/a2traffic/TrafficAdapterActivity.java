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
import java.io.InputStream;
import java.io.OutputStream;
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
    private static final String ACTION_B1_PROBE =
            "com.sakamoto.snort.a2traffic.B1_PROBE";
    private static final String ACTION_RETURN =
            "com.sakamoto.snort.a2traffic.A2_3_RETURN";
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
    private static final String B1_EVIDENCE_PATH = "debug/b1-runtime.jsonl";
    private static final String B1_SCHEMA = "s139-b1-runtime/v1";
    private static final String RETURN_EVIDENCE_PATH =
            "debug/a2-3-return-runtime.jsonl";
    private static final String RETURN_SCHEMA = "s139-a2-3-return/v1";
    private static final String RETURN_STAGE_ID = "A2-3-udp4-return";
    private static final String RETURN_PAYLOAD_PREFIX = "s139-a2-3|";
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
        if (intent == null) {
            return;
        }
        if (isB1Command(intent)) {
            final B1Command command = B1Command.from(intent);
            Thread worker = new Thread(() -> runB1Operation(command),
                    "s139-b1-traffic");
            worker.start();
            return;
        }
        if (isReturnCommand(intent)) {
            final ReturnCommand command = ReturnCommand.from(intent);
            Thread worker = new Thread(() -> runReturnOperation(command),
                    "s139-a2-3-return");
            worker.start();
            return;
        }
        if (!isEmitCommand(intent)) {
            return;
        }
        final Command command = Command.from(intent);
        Thread worker = new Thread(() -> {
            if (isA25Stage(command.stageId)) {
                runA25Operation(command);
            } else {
                for (int index = 1; index <= command.repeat; index++) {
                    runOperation(command, index, command.repeat);
                }
            }
        }, "s139-a2-1-traffic");
        worker.start();
    }

    private static boolean isA25Stage(String stageId) {
        return stageId != null && stageId.startsWith("A2-5-");
    }

    private boolean isEmitCommand(Intent intent) {
        return ACTION_EMIT.equals(intent.getAction())
                || intent.getBooleanExtra(EXTRA_MATRIX, false);
    }

    private boolean isB1Command(Intent intent) {
        return ACTION_B1_PROBE.equals(intent.getAction())
                || intent.getBooleanExtra("b1Probe", false);
    }

    private boolean isReturnCommand(Intent intent) {
        return ACTION_RETURN.equals(intent.getAction())
                || intent.getBooleanExtra("a2Return", false);
    }

    /**
     * A2-3 is deliberately a separate operation from the A2-1 cache probe.
     * The same bound DatagramSocket stays open through send and receive, so a
     * successful record proves the real App UID received the Flow Stack
     * return packet rather than merely observing a native output counter.
     */
    private void runReturnOperation(ReturnCommand command) {
        long sequence = SEQUENCE.incrementAndGet();
        int uid = Process.myUid();
        String packageName = getPackageName();
        ReturnResult result = performReturn(command);
        JSONObject record = returnRecord(command, result, sequence,
                SystemClock.elapsedRealtimeNanos(), packageName, uid);
        appendReturnRecord(record);
        runOnUiThread(() -> {
            TextView view = new TextView(this);
            view.setText("A2-3 " + command.stageId + " " + result.outcome);
            setContentView(view);
        });
    }

    private ReturnResult performReturn(ReturnCommand command) {
        if (!command.validationError.isEmpty()) {
            return ReturnResult.failure(-1L, "not_attempted", "",
                    command.destinationHost, "invalid_command", false,
                    command.validationError, "", "", 0, 0, "", 0);
        }
        Network network = findVpnNetwork();
        if (network == null) {
            return ReturnResult.failure(-1L, "unavailable", "", "",
                    "vpn_unavailable", false, "no_active_transport_vpn",
                    "", "", 0, 0, "", 0);
        }
        InetAddress destination;
        try {
            destination = resolveDestination(command.destinationHost,
                    command.family);
        } catch (IOException error) {
            return ReturnResult.failure(network.getNetworkHandle(),
                    "not_attempted", "", command.destinationHost,
                    "destination_resolution_failed", false,
                    boundedError(error), "", "", 0, 0, "", 0);
        }

        DatagramSocket socket = null;
        String bindResult = "not_attempted";
        boolean tupleAttempted = false;
        byte[] payload = (RETURN_PAYLOAD_PREFIX + command.stageId)
                .getBytes(StandardCharsets.UTF_8);
        try {
            socket = new DatagramSocket(null);
            socket.setReuseAddress(true);
            socket.bind(new InetSocketAddress(wildcard(command.family),
                    command.sourcePort));
            try {
                // The socket itself crosses the real App -> VPN admission
                // seam.  Do not use process-wide bind or a native-only probe.
                network.bindSocket(socket);
                bindResult = "bound";
            } catch (IOException | RuntimeException error) {
                bindResult = "failed";
                return ReturnResult.failure(network.getNetworkHandle(),
                        bindResult, localAddress(socket, network, command.family),
                        destination.getHostAddress(), "vpn_bind_failed", false,
                        boundedError(error), toHex(payload), "", payload.length,
                        0, "", 0);
            }
            tupleAttempted = true;
            socket.connect(destination, command.destinationPort);
            String local = localAddress(socket, network, command.family);
            socket.setSoTimeout(command.timeoutMillis);
            socket.send(new DatagramPacket(payload, payload.length));
            byte[] received = new byte[payload.length + 128];
            DatagramPacket response = new DatagramPacket(received,
                    received.length);
            try {
                socket.receive(response);
                byte[] actual = new byte[response.getLength()];
                System.arraycopy(response.getData(), response.getOffset(),
                        actual, 0, response.getLength());
                boolean exact = java.util.Arrays.equals(payload, actual);
                String outcome = exact ? "udp_roundtrip_received"
                        : "udp_roundtrip_payload_mismatch";
                return ReturnResult.failure(network.getNetworkHandle(),
                        bindResult, local, destination.getHostAddress(), outcome,
                        tupleAttempted, exact ? "" : "payload_mismatch",
                        toHex(payload), toHex(actual), payload.length,
                        actual.length, response.getAddress() == null ? ""
                                : response.getAddress().getHostAddress(),
                        response.getPort());
            } catch (java.net.SocketTimeoutException timeout) {
                return ReturnResult.failure(network.getNetworkHandle(),
                        bindResult, local, destination.getHostAddress(),
                        "udp_roundtrip_timeout", tupleAttempted,
                        boundedError(timeout), toHex(payload), "",
                        payload.length, 0, "", 0);
            }
        } catch (IOException | RuntimeException error) {
            String local = socket == null ? ""
                    : localAddress(socket, network, command.family);
            return ReturnResult.failure(network.getNetworkHandle(), bindResult,
                    local, destination.getHostAddress(),
                    "udp_roundtrip_failed", tupleAttempted,
                    boundedError(error), toHex(payload), "", payload.length,
                    0, "", 0);
        } finally {
            if (socket != null) {
                socket.close();
            }
        }
    }

    private JSONObject returnRecord(ReturnCommand command, ReturnResult result,
                                    long sequence, long monotonicNs,
                                    String packageName, int uid) {
        SafeJson record = new SafeJson();
        record.putSafe("schema", RETURN_SCHEMA);
        record.putSafe("cell_id", "A2-3");
        record.putSafe("stage_id", command.stageId);
        record.putSafe("sequence", sequence);
        record.putSafe("monotonic_ns", monotonicNs);
        record.putSafe("generation", 1);
        record.putSafe("network_epoch", 1);
        record.putSafe("app_epoch", 1);
        record.putSafe("event", "RETURN_ROUNDTRIP");
        record.putSafe("app_package", packageName);
        record.putSafe("package", packageName);
        record.putSafe("uid", uid);
        record.putSafe("process_uid", uid);
        record.putSafe("family", command.family);
        record.putSafe("protocol", "udp");
        record.putSafe("source_address", result.localAddress);
        record.putSafe("source_port", command.sourcePort);
        record.putSafe("destination_address", result.destinationAddress);
        record.putSafe("destination_host", command.destinationHost);
        record.putSafe("destination_port", command.destinationPort);
        record.putSafe("canonical_key", canonicalKey(command.family,
                result.localAddress, command.sourcePort,
                result.destinationAddress, command.destinationPort));
        record.putSafe("bind_result", result.bindResult);
        record.putSafe("vpn_network_handle", result.networkHandle);
        record.putSafe("tuple_attempted", result.tupleAttempted);
        record.putSafe("send_connect_outcome", result.outcome);
        record.putSafe("error", result.error);
        record.putSafe("payload_hex", result.payloadHex);
        record.putSafe("payload_length", result.payloadLength);
        record.putSafe("received_payload_hex", result.receivedPayloadHex);
        record.putSafe("received_length", result.receivedLength);
        record.putSafe("received_from_address", result.receivedFromAddress);
        record.putSafe("received_from_port", result.receivedFromPort);
        record.putSafe("return_received",
                "udp_roundtrip_received".equals(result.outcome));
        record.putSafe("android_lookup_count", 0);
        record.putSafe("flow_id", command.stageId + "|udp|"
                + command.sourcePort);
        return record;
    }

    private void appendReturnRecord(JSONObject record) {
        File file = new File(getFilesDir(), RETURN_EVIDENCE_PATH);
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
                Log.e(TAG, "unable to durably append A2-3 JSONL", error);
            }
        }
    }

    private static String toHex(byte[] bytes) {
        StringBuilder hex = new StringBuilder(bytes.length * 2);
        for (byte value : bytes) {
            hex.append(String.format("%02x", value & 0xff));
        }
        return hex.toString();
    }

    private static String canonicalKey(String family, String sourceAddress,
                                       int sourcePort,
                                       String destinationAddress,
                                       int destinationPort) {
        String source = formatEndpoint(sourceAddress, family) + ":" + sourcePort;
        String destination = formatEndpoint(destinationAddress, family) + ":"
                + destinationPort;
        String first = source.compareTo(destination) <= 0 ? source : destination;
        String second = source.compareTo(destination) <= 0 ? destination : source;
        return family + "/UDP/" + first + "-" + second;
    }

    private void runB1Operation(B1Command command) {
        long sequence = SEQUENCE.incrementAndGet();
        int uid = Process.myUid();
        String packageName = getPackageName();
        B1Result result;
        if (!command.validationError.isEmpty()) {
            result = B1Result.invalid(command.validationError,
                    command.destinationHost);
        } else {
            result = performB1Probe(command);
        }
        SafeJson record = new SafeJson();
        record.putSafe("schema", B1_SCHEMA);
        record.putSafe("cell_id", "B1");
        record.putSafe("stage_id", command.stageId);
        record.putSafe("sequence", sequence);
        record.putSafe("monotonic_ns", SystemClock.elapsedRealtimeNanos());
        record.putSafe("generation", 1);
        record.putSafe("network_epoch", 1);
        record.putSafe("app_epoch", 1);
        record.putSafe("event", "B1_TRAFFIC_RESULT");
        record.putSafe("app_package", packageName);
        record.putSafe("package", packageName);
        record.putSafe("uid", uid);
        record.putSafe("process_uid", uid);
        record.putSafe("family", command.family);
        record.putSafe("protocol", command.protocol);
        record.putSafe("dns", command.dns);
        record.putSafe("tcp_write_mode", command.tcpWriteMode);
        record.putSafe("fallback_tcp_on_truncated",
                command.fallbackTcpOnTruncated);
        record.putSafe("fallback_source_port", result.fallbackSourcePort);
        record.putSafe("fallback_attempted", result.fallbackAttempted);
        record.putSafe("fallback_reason", result.fallbackReason);
        record.putSafe("fallback_return_outcome", result.fallbackReturnOutcome);
        record.putSafe("udp_truncated", result.udpTruncated);
        record.putSafe("udp_received_length", result.udpReceivedLength);
        record.putSafe("tcp_received_length", result.tcpReceivedLength);
        record.putSafe("tcp_response_valid", result.tcpResponseValid);
        record.putSafe("source_address", result.localAddress);
        record.putSafe("source_port", command.sourcePort);
        record.putSafe("destination_address", result.destinationAddress);
        record.putSafe("destination_host", command.destinationHost);
        record.putSafe("destination_port", command.destinationPort);
        record.putSafe("bind_result", result.bindResult);
        record.putSafe("vpn_network_handle", result.networkHandle);
        record.putSafe("tuple_attempted", result.tupleAttempted);
        record.putSafe("send_connect_outcome", result.sendConnectOutcome);
        record.putSafe("return_outcome", result.returnOutcome);
        record.putSafe("return_received", result.returnReceived());
        record.putSafe("response_valid", result.responseValid);
        record.putSafe("payload_hex", result.payloadHex());
        record.putSafe("received_payload_hex", result.receivedPayloadHex());
        record.putSafe("payload_length", result.payloadLength());
        record.putSafe("received_length", result.receivedLength());
        record.putSafe("error", result.error);
        record.putSafe("flow_id", command.stageId + "|" + command.family
                + "|" + command.protocol + "|" + command.sourcePort);
        record.putSafe("canonical_key", command.family + "|"
                + command.protocol + "|" + command.sourcePort + "|"
                + formatEndpoint(result.destinationAddress, command.family)
                + ":" + command.destinationPort);
        appendB1Record(record);
        setB1Status(command.stageId, result.sendConnectOutcome + "/"
                + result.returnOutcome);
    }

    private B1Result performB1Probe(B1Command command) {
        Network network = findVpnNetwork();
        if (network == null) {
            return B1Result.unavailable(command.destinationHost,
                    "no_active_transport_vpn");
        }
        long networkHandle = network.getNetworkHandle();
        InetAddress destination;
        try {
            destination = resolveDestination(command.destinationHost,
                    command.family);
        } catch (IOException error) {
            return B1Result.notAttempted(networkHandle,
                    command.destinationHost, "destination_resolution_failed",
                    boundedError(error));
        }
        byte[] payload;
        try {
            payload = decodeHex(command.payloadHex);
        } catch (IllegalArgumentException error) {
            return B1Result.notAttempted(networkHandle,
                    destination.getHostAddress(), "invalid_payload",
                    boundedError(error));
        }
        if ("udp".equals(command.protocol)) {
            return performB1Udp(network, networkHandle, command, destination,
                    payload);
        }
        return performB1Tcp(network, networkHandle, command, destination,
                payload);
    }

    private B1Result performB1Udp(Network network, long networkHandle,
                                   B1Command command, InetAddress destination,
                                   byte[] payload) {
        DatagramSocket socket = null;
        String bindResult = "not_attempted";
        boolean tupleAttempted = false;
        try {
            socket = new DatagramSocket(null);
            socket.setReuseAddress(true);
            socket.bind(new InetSocketAddress(wildcard(command.family),
                    command.sourcePort));
            try {
                network.bindSocket(socket);
                bindResult = "bound";
            } catch (IOException | RuntimeException error) {
                bindResult = "failed";
                return B1Result.failure(networkHandle, bindResult,
                        localAddress(socket, network, command.family),
                        destination.getHostAddress(), "vpn_bind_failed",
                        "not_attempted", false, boundedError(error),
                        payload, new byte[0], false);
            }
            tupleAttempted = true;
            socket.connect(destination, command.destinationPort);
            socket.setSoTimeout(command.timeoutMillis);
            socket.send(new DatagramPacket(payload, payload.length));
            if (!command.dns) {
                return B1Result.success(networkHandle, bindResult,
                        localAddress(socket, network, command.family),
                        destination.getHostAddress(), "udp_datagram_sent",
                        "not_required", tupleAttempted, "", payload,
                        new byte[0], false);
            }
            byte[] received = new byte[4096];
            DatagramPacket response = new DatagramPacket(received,
                    received.length);
            try {
                socket.receive(response);
                byte[] actual = copyPacket(response);
                boolean valid = validDnsResponse(payload, actual);
                boolean truncated = dnsResponseTruncated(actual);
                if (valid && truncated && command.fallbackTcpOnTruncated) {
                    B1Command fallback = command.tcpFallbackCommand();
                    B1Result tcpResult = performB1Tcp(network, networkHandle,
                            fallback, destination, payload);
                    return B1Result.fallback(networkHandle, bindResult,
                            localAddress(socket, network, command.family),
                            destination.getHostAddress(),
                            "udp_datagram_sent",
                            tcpResult.responseValid
                                    ? "dns_tcp_fallback_response_received"
                                    : "dns_tcp_fallback_failed",
                            tupleAttempted, tcpResult.error, payload,
                            tcpResult.received, tcpResult.responseValid,
                            true, command.fallbackTcpSourcePort,
                            "udp_tc", tcpResult.returnOutcome,
                            actual.length, tcpResult.receivedLength(),
                            tcpResult.responseValid);
                }
                return B1Result.success(networkHandle, bindResult,
                        localAddress(socket, network, command.family),
                        destination.getHostAddress(), "udp_datagram_sent",
                        valid ? "dns_response_received"
                                : "dns_response_invalid", tupleAttempted,
                        valid ? "" : "dns_response_shape_invalid", payload,
                        actual, valid);
            } catch (SocketTimeoutException timeout) {
                return B1Result.success(networkHandle, bindResult,
                        localAddress(socket, network, command.family),
                        destination.getHostAddress(), "udp_datagram_sent",
                        "dns_response_timeout", tupleAttempted,
                        boundedError(timeout), payload, new byte[0], false);
            }
        } catch (IOException | RuntimeException error) {
            String local = socket == null ? ""
                    : localAddress(socket, network, command.family);
            return B1Result.failure(networkHandle, bindResult, local,
                    destination.getHostAddress(), "udp_datagram_failed",
                    "not_attempted", tupleAttempted, boundedError(error),
                    payload, new byte[0], false);
        } finally {
            if (socket != null) {
                socket.close();
            }
        }
    }

    private B1Result performB1Tcp(Network network, long networkHandle,
                                  B1Command command, InetAddress destination,
                                  byte[] payload) {
        Socket socket = null;
        String bindResult = "not_attempted";
        boolean tupleAttempted = false;
        boolean connected = false;
        boolean payloadSent = false;
        try {
            socket = new Socket();
            socket.setReuseAddress(true);
            socket.bind(new InetSocketAddress(wildcard(command.family),
                    command.sourcePort));
            try {
                network.bindSocket(socket);
                bindResult = "bound";
            } catch (IOException | RuntimeException error) {
                bindResult = "failed";
                return B1Result.failure(networkHandle, bindResult,
                        localAddress(socket, network, command.family),
                        destination.getHostAddress(), "vpn_bind_failed",
                        "not_attempted", false, boundedError(error),
                        payload, new byte[0], false);
            }
            tupleAttempted = true;
            socket.connect(new InetSocketAddress(destination,
                    command.destinationPort), command.timeoutMillis);
            connected = true;
            String local = localAddress(socket, network, command.family);
            if (!command.dns) {
                return B1Result.success(networkHandle, bindResult, local,
                        destination.getHostAddress(), "tcp_connect_succeeded",
                        "not_required", tupleAttempted, "", payload,
                        new byte[0], false);
            }
            socket.setSoTimeout(command.timeoutMillis);
            OutputStream output = socket.getOutputStream();
            if ("coalesced".equals(command.tcpWriteMode)) {
                byte[] framed = new byte[payload.length + 2];
                framed[0] = (byte) ((payload.length >>> 8) & 0xff);
                framed[1] = (byte) (payload.length & 0xff);
                System.arraycopy(payload, 0, framed, 2, payload.length);
                output.write(framed);
            } else {
                // Deliberately preserve three separate writes: this is the
                // regression arm for a stream that arrives as multiple TUN
                // packets, not a fixture that hides segmentation by packing
                // the DNS frame in one syscall.
                output.write((payload.length >>> 8) & 0xff);
                output.write(payload.length & 0xff);
                output.write(payload);
            }
            output.flush();
            payloadSent = true;
            InputStream input = socket.getInputStream();
            int high = input.read();
            int low = high < 0 ? -1 : input.read();
            if (high < 0 || low < 0) {
                return B1Result.success(networkHandle, bindResult, local,
                        destination.getHostAddress(), "tcp_payload_sent",
                        "dns_response_eof", tupleAttempted, "", payload,
                        new byte[0], false);
            }
            int length = (high << 8) | low;
            byte[] actual = readFully(input, length);
            boolean valid = validDnsResponse(payload, actual);
            return B1Result.success(networkHandle, bindResult, local,
                    destination.getHostAddress(), "tcp_payload_sent",
                    valid ? "dns_response_received" : "dns_response_invalid",
                    tupleAttempted, valid ? "" : "dns_response_shape_invalid",
                    payload, actual, valid);
        } catch (SocketTimeoutException timeout) {
            String local = socket == null ? ""
                    : localAddress(socket, network, command.family);
            return B1Result.success(networkHandle, bindResult, local,
                    destination.getHostAddress(), "tcp_connect_succeeded",
                    "dns_response_timeout", tupleAttempted,
                    boundedError(timeout), payload, new byte[0], false);
        } catch (IOException | RuntimeException error) {
            String local = socket == null ? ""
                    : localAddress(socket, network, command.family);
            String errorText = boundedError(error);
            String lowerError = errorText.toLowerCase(java.util.Locale.ROOT);
            if (connected) {
                boolean reset = error instanceof java.net.SocketException
                        && (lowerError.contains("reset")
                        || lowerError.contains("econnreset"));
                return B1Result.success(networkHandle, bindResult, local,
                        destination.getHostAddress(),
                        payloadSent ? "tcp_payload_sent"
                                : "tcp_connect_succeeded",
                        reset ? "dns_response_reset"
                                : "dns_response_io_error",
                        tupleAttempted, errorText, payload,
                        new byte[0], false);
            }
            return B1Result.failure(networkHandle, bindResult, local,
                    destination.getHostAddress(), "tcp_connect_failed",
                    "not_attempted", tupleAttempted, errorText,
                    payload, new byte[0], false);
        } finally {
            if (socket != null) {
                try {
                    socket.close();
                } catch (IOException ignored) {
                    // Preserve the transport result over close noise.
                }
            }
        }
    }

    private void appendB1Record(JSONObject record) {
        File file = new File(getFilesDir(), B1_EVIDENCE_PATH);
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
                Log.e(TAG, "unable to durably append B1 JSONL", error);
            }
        }
    }

    private void setB1Status(final String stageId, final String outcome) {
        runOnUiThread(() -> {
            TextView view = new TextView(this);
            view.setText("B1 " + stageId + " " + outcome);
            setContentView(view);
        });
    }

    private static byte[] copyPacket(DatagramPacket packet) {
        byte[] actual = new byte[packet.getLength()];
        System.arraycopy(packet.getData(), packet.getOffset(), actual, 0,
                packet.getLength());
        return actual;
    }

    private static byte[] readFully(InputStream input, int length)
            throws IOException {
        if (length < 0 || length > 65535) {
            throw new IOException("invalid DNS/TCP response length " + length);
        }
        byte[] result = new byte[length];
        int offset = 0;
        while (offset < length) {
            int count = input.read(result, offset, length - offset);
            if (count < 0) {
                throw new IOException("short DNS/TCP response");
            }
            offset += count;
        }
        return result;
    }

    private static boolean validDnsResponse(byte[] query, byte[] response) {
        if (query == null || query.length < 12 || response == null
                || response.length < 12) {
            return false;
        }
        int queryId = ((query[0] & 0xff) << 8) | (query[1] & 0xff);
        int responseId = ((response[0] & 0xff) << 8) | (response[1] & 0xff);
        int flags = ((response[2] & 0xff) << 8) | (response[3] & 0xff);
        int rcode = flags & 0x0f;
        return queryId == responseId && (flags & 0x8000) != 0 && rcode == 0;
    }

    private static boolean dnsResponseTruncated(byte[] response) {
        if (response == null || response.length < 4) {
            return false;
        }
        int flags = ((response[2] & 0xff) << 8) | (response[3] & 0xff);
        return (flags & 0x0200) != 0;
    }

    private static byte[] decodeHex(String value) {
        if (value == null || value.isEmpty()) {
            return new byte[0];
        }
        if ((value.length() & 1) != 0) {
            throw new IllegalArgumentException("payloadHex must have even length");
        }
        byte[] bytes = new byte[value.length() / 2];
        for (int i = 0; i < bytes.length; i++) {
            int high = Character.digit(value.charAt(i * 2), 16);
            int low = Character.digit(value.charAt(i * 2 + 1), 16);
            if (high < 0 || low < 0) {
                throw new IllegalArgumentException("payloadHex is not hexadecimal");
            }
            bytes[i] = (byte) ((high << 4) | low);
        }
        return bytes;
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
        appendOperationRecord(command, result, sequence, monotonicNs,
                repeatIndex, repeatCount, packageName, uid, false);
        setStatus(command.stageId, result.outcome);
    }

    /**
     * A2-5 keeps one real AppA socket alive across the repeated sends.  The
     * Android owner resolver is asynchronous and may not be able to attribute
     * a short-lived UDP socket after the first send has already been closed.
     * Keeping the exact bound socket alive makes the second resolver query a
     * real observation of the same canonical tuple rather than a new socket
     * with an ambiguous lifetime.  This branch is intentionally scoped to the
     * A2-5 admission cell; the historical A2-1/A2-2 repeat semantics remain
     * close-and-recreate.
     */
    private void runA25Operation(Command command) {
        int uid = Process.myUid();
        String packageName = getPackageName();
        if (!command.validationError.isEmpty()) {
            runOperation(command, 1, command.repeat);
            return;
        }

        Network network = findVpnNetwork();
        if (network == null) {
            runOperation(command, 1, command.repeat);
            return;
        }
        long networkHandle = network.getNetworkHandle();
        InetAddress destination;
        try {
            destination = resolveDestination(command.destinationHost,
                    command.family);
        } catch (IOException error) {
            ProbeResult result = ProbeResult.notAttempted(networkHandle,
                    command.destinationHost, "destination_resolution_failed",
                    boundedError(error));
            appendOperationRecord(command, result, SEQUENCE.incrementAndGet(),
                    SystemClock.elapsedRealtimeNanos(), 1, command.repeat,
                    packageName, uid, true);
            setStatus(command.stageId, result.outcome);
            return;
        }

        DatagramSocket socket = null;
        String bindResult = "not_attempted";
        boolean tupleAttempted = false;
        int nextRepeat = 1;
        try {
            socket = new DatagramSocket(null);
            socket.setReuseAddress(true);
            socket.bind(new InetSocketAddress(wildcard(command.family),
                    command.sourcePort));
            try {
                // This is the real App -> VPN admission boundary.  The same
                // bound descriptor is deliberately retained for all sends.
                network.bindSocket(socket);
                bindResult = "bound";
            } catch (IOException | RuntimeException error) {
                bindResult = "failed";
                ProbeResult result = ProbeResult.failure(networkHandle,
                        bindResult, localAddress(socket, network, command.family),
                        destination.getHostAddress(), "vpn_bind_failed", false,
                        boundedError(error));
                appendOperationRecord(command, result,
                        SEQUENCE.incrementAndGet(),
                        SystemClock.elapsedRealtimeNanos(), nextRepeat,
                        command.repeat, packageName, uid, true);
                setStatus(command.stageId, result.outcome);
                return;
            }
            tupleAttempted = true;
            String local = localAddress(socket, network, command.family);
            byte[] payload = ("s139-a2-5|" + command.stageId)
                    .getBytes(StandardCharsets.UTF_8);
            for (; nextRepeat <= command.repeat; nextRepeat++) {
                // Keep the A2-5 UDP shape identical to the historical
                // Androidruntime control fixture: an explicitly addressed
                // datagram on a bound, but unconnected, socket.  The Android
                // owner API has observed this shape reliably on the target
                // device, whereas connected UDP can return -1 for the same
                // tuple even while the descriptor is still live.
                socket.send(new DatagramPacket(payload, payload.length,
                        destination, command.destinationPort));
                ProbeResult result = ProbeResult.success(networkHandle,
                        bindResult, local, destination.getHostAddress(),
                        "udp_datagram_sent", tupleAttempted, "");
                appendOperationRecord(command, result,
                        SEQUENCE.incrementAndGet(),
                        SystemClock.elapsedRealtimeNanos(), nextRepeat,
                        command.repeat, packageName, uid, true);
                setStatus(command.stageId, result.outcome);
                // Keep the descriptor live after the final send as well so
                // the asynchronous owner lookup can settle before close().
                if (command.timeoutMillis > 0) {
                    SystemClock.sleep(Math.min(command.timeoutMillis, 3000));
                }
            }
        } catch (IOException | RuntimeException error) {
            String local = socket == null ? ""
                    : localAddress(socket, network, command.family);
            ProbeResult result = ProbeResult.failure(networkHandle, bindResult,
                    local, destination.getHostAddress(), "udp_datagram_failed",
                    tupleAttempted, boundedError(error));
            appendOperationRecord(command, result, SEQUENCE.incrementAndGet(),
                    SystemClock.elapsedRealtimeNanos(), nextRepeat,
                    command.repeat, packageName, uid, true);
            setStatus(command.stageId, result.outcome);
        } finally {
            if (socket != null) {
                socket.close();
            }
        }
    }

    private void appendOperationRecord(Command command, ProbeResult result,
                                       long sequence, long monotonicNs,
                                       int repeatIndex, int repeatCount,
                                       String packageName, int uid,
                                       boolean socketReused) {
        JSONObject record = operationRecord(command, result, sequence,
                monotonicNs, repeatIndex, repeatCount, packageName, uid,
                socketReused);
        appendRecord(record);
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
                        localPort(socket),
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
                    localPort(socket),
                    destination.getHostAddress(), "udp_datagram_sent",
                    tupleAttempted, "");
        } catch (IOException | RuntimeException error) {
            String local = socket == null ? ""
                    : localAddress(socket, network, command.family);
            return ProbeResult.failure(networkHandle, bindResult, local,
                    localPort(socket),
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
                        localPort(socket),
                        destination.getHostAddress(), "vpn_bind_failed", false,
                        boundedError(error));
            }
            tupleAttempted = true;
            socket.connect(new InetSocketAddress(destination,
                    command.destinationPort), command.timeoutMillis);
            String local = localAddress(socket, network, command.family);
            return ProbeResult.success(networkHandle, bindResult, local,
                    localPort(socket),
                    destination.getHostAddress(), "tcp_connect_succeeded",
                    tupleAttempted, "");
        } catch (SocketTimeoutException error) {
            String local = socket == null ? ""
                    : localAddress(socket, network, command.family);
            return ProbeResult.failure(networkHandle, bindResult, local,
                    localPort(socket),
                    destination.getHostAddress(), "tcp_connect_timeout",
                    tupleAttempted, boundedError(error));
        } catch (IOException | RuntimeException error) {
            String local = socket == null ? ""
                    : localAddress(socket, network, command.family);
            return ProbeResult.failure(networkHandle, bindResult, local,
                    localPort(socket),
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

    private int localPort(Object socket) {
        if (socket instanceof Socket) {
            return ((Socket) socket).getLocalPort();
        }
        if (socket instanceof DatagramSocket) {
            return ((DatagramSocket) socket).getLocalPort();
        }
        return -1;
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
        return operationRecord(command, result, sequence, monotonicNs,
                repeatIndex, repeatCount, packageName, uid, false);
    }

    private JSONObject operationRecord(Command command, ProbeResult result,
                                       long sequence, long monotonicNs,
                                       int repeatIndex, int repeatCount,
                                       String packageName, int uid,
                                       boolean socketReused) {
        int effectiveSourcePort = result.localPort > 0
                ? result.localPort : command.sourcePort;
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
        record.putSafe("source_port", effectiveSourcePort);
        record.putSafe("requested_source_port", command.sourcePort);
        record.putSafe("destination_address", result.destinationAddress);
        record.putSafe("destination_host", command.destinationHost);
        record.putSafe("destination_port", command.destinationPort);
        record.putSafe("bind_result", result.bindResult);
        record.putSafe("vpn_network_handle", result.networkHandle);
        record.putSafe("actual_local_address", result.localAddress);
        record.putSafe("actual_local_port", result.localPort);
        record.putSafe("send_connect_outcome", result.outcome);
        record.putSafe("tuple_attempted", result.tupleAttempted);
        record.putSafe("error", result.error);
        record.putSafe("repeat_index", repeatIndex);
        record.putSafe("repeat_count", repeatCount);
        record.putSafe("socket_reused_for_repeat", socketReused);
        record.putSafe("flow_id", command.stageId + "|" + command.family
                + "|" + command.protocol + "|" + effectiveSourcePort);
        record.putSafe("token", command.stageId + "-" + sequence);
        record.putSafe("canonical_key", command.family + "|"
                + command.protocol + "|" + effectiveSourcePort + "|"
                + formatEndpoint(result.destinationAddress, command.family)
                + ":" + command.destinationPort);

        SafeJson source = new SafeJson();
        source.putSafe("address", result.localAddress);
        source.putSafe("port", effectiveSourcePort);
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
        record.putSafe("sourcePort", effectiveSourcePort);
        record.putSafe("requestedSourcePort", command.sourcePort);
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
            } else if (!validSourcePort(protocol, sourcePort)
                    || !validPort(destinationPort)) {
                error = "source port must be 1..65535, or 0 for TCP ephemeral; "
                        + "destination port must be 1..65535";
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

        private static boolean validSourcePort(String protocol, int port) {
            if ("tcp".equals(protocol) && port == 0) {
                return true;
            }
            return validPort(port);
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

    private static final class ReturnCommand {
        final String stageId;
        final String family;
        final int sourcePort;
        final String destinationHost;
        final int destinationPort;
        final int timeoutMillis;
        final String validationError;

        private ReturnCommand(String stageId, String family, int sourcePort,
                              String destinationHost, int destinationPort,
                              int timeoutMillis, String validationError) {
            this.stageId = stageId;
            this.family = family;
            this.sourcePort = sourcePort;
            this.destinationHost = destinationHost;
            this.destinationPort = destinationPort;
            this.timeoutMillis = timeoutMillis;
            this.validationError = validationError;
        }

        static ReturnCommand from(Intent intent) {
            String stageId = stringExtra(intent, "a2ReturnStageId", null,
                    RETURN_STAGE_ID);
            String family = stringExtra(intent, "a2ReturnFamily", null, "ip4");
            int sourcePort = intExtra(intent, "a2ReturnSourcePort", null,
                    45841);
            String defaultHost = "ip6".equalsIgnoreCase(family)
                    ? "fd00:200::1" : "10.200.0.1";
            String destinationHost = stringExtra(intent, "a2ReturnDestinationHost",
                    null, defaultHost);
            int destinationPort = intExtra(intent, "a2ReturnDestinationPort",
                    null, 42081);
            int timeout = intExtra(intent, "a2ReturnTimeoutMillis", null, 3500);
            String error = "";
            if (!"ip4".equalsIgnoreCase(family)
                    && !"ip6".equalsIgnoreCase(family)) {
                error = "family must be ip4 or ip6";
            } else if (!validPort(sourcePort) || !validPort(destinationPort)) {
                error = "source and destination ports must be 1..65535";
            } else if (timeout < 100 || timeout > 10000) {
                error = "timeoutMillis must be 100..10000";
                timeout = Math.max(100, Math.min(timeout, 10000));
            }
            return new ReturnCommand(stageId,
                    "ip6".equalsIgnoreCase(family) ? "ip6" : "ip4",
                    sourcePort, stripIpv6Brackets(destinationHost),
                    destinationPort, timeout, error);
        }

        private static boolean validPort(int port) {
            return port >= 1 && port <= 65535;
        }
    }

    private static final class ReturnResult {
        final String bindResult;
        final long networkHandle;
        final String localAddress;
        final String destinationAddress;
        final String outcome;
        final boolean tupleAttempted;
        final String error;
        final String payloadHex;
        final String receivedPayloadHex;
        final int payloadLength;
        final int receivedLength;
        final String receivedFromAddress;
        final int receivedFromPort;

        private ReturnResult(String bindResult, long networkHandle,
                             String localAddress, String destinationAddress,
                             String outcome, boolean tupleAttempted,
                             String error, String payloadHex,
                             String receivedPayloadHex, int payloadLength,
                             int receivedLength, String receivedFromAddress,
                             int receivedFromPort) {
            this.bindResult = bindResult;
            this.networkHandle = networkHandle;
            this.localAddress = localAddress == null ? "" : localAddress;
            this.destinationAddress = destinationAddress == null ? ""
                    : destinationAddress;
            this.outcome = outcome;
            this.tupleAttempted = tupleAttempted;
            this.error = error == null ? "" : error;
            this.payloadHex = payloadHex == null ? "" : payloadHex;
            this.receivedPayloadHex = receivedPayloadHex == null ? ""
                    : receivedPayloadHex;
            this.payloadLength = payloadLength;
            this.receivedLength = receivedLength;
            this.receivedFromAddress = receivedFromAddress == null ? ""
                    : receivedFromAddress;
            this.receivedFromPort = receivedFromPort;
        }

        static ReturnResult failure(long handle, String bindResult,
                                    String localAddress,
                                    String destinationAddress, String outcome,
                                    boolean attempted, String error,
                                    String payloadHex,
                                    String receivedPayloadHex,
                                    int payloadLength, int receivedLength,
                                    String receivedFromAddress,
                                    int receivedFromPort) {
            return new ReturnResult(bindResult, handle, localAddress,
                    destinationAddress, outcome, attempted, error, payloadHex,
                    receivedPayloadHex, payloadLength, receivedLength,
                    receivedFromAddress, receivedFromPort);
        }
    }

    private static final class B1Command {
        final String stageId;
        final String family;
        final String protocol;
        final int sourcePort;
        final String destinationHost;
        final int destinationPort;
        final int timeoutMillis;
        final boolean dns;
        final String payloadHex;
        final String tcpWriteMode;
        final boolean fallbackTcpOnTruncated;
        final int fallbackTcpSourcePort;
        final String validationError;

        private B1Command(String stageId, String family, String protocol,
                          int sourcePort, String destinationHost,
                          int destinationPort, int timeoutMillis,
                          boolean dns, String payloadHex,
                          String tcpWriteMode, boolean fallbackTcpOnTruncated,
                          int fallbackTcpSourcePort,
                          String validationError) {
            this.stageId = stageId;
            this.family = family;
            this.protocol = protocol;
            this.sourcePort = sourcePort;
            this.destinationHost = destinationHost;
            this.destinationPort = destinationPort;
            this.timeoutMillis = timeoutMillis;
            this.dns = dns;
            this.payloadHex = payloadHex;
            this.tcpWriteMode = tcpWriteMode;
            this.fallbackTcpOnTruncated = fallbackTcpOnTruncated;
            this.fallbackTcpSourcePort = fallbackTcpSourcePort;
            this.validationError = validationError;
        }

        static B1Command from(Intent intent) {
            String stage = stringExtra(intent, "b1StageId", "stageId", "B1");
            String rawFamily = stringExtra(intent, "b1Family", "family", "ip4");
            String rawProtocol = stringExtra(intent, "b1Protocol", "protocol", "udp");
            String family = normalizeFamily(rawFamily);
            String protocol = normalizeProtocol(rawProtocol);
            int sourcePort = intExtra(intent, "b1SourcePort", "sourcePort", 46100);
            int destinationPort = intExtra(intent, "b1DestinationPort",
                    "destinationPort", "udp".equals(protocol) ? 53 : 443);
            String host = stringExtra(intent, "b1DestinationHost",
                    "destinationHost", defaultDestinationHost(family));
            int timeout = intExtra(intent, "b1TimeoutMillis",
                    "timeoutMillis", 3000);
            boolean dns = intent.getBooleanExtra("b1Dns", false);
            String tcpWriteMode = stringExtra(intent, "b1TcpWriteMode",
                    "tcpWriteMode", "separate").toLowerCase();
            boolean fallbackTcpOnTruncated =
                    intent.getBooleanExtra("b1FallbackTcpOnTruncated", false);
            int fallbackDefaultPort = sourcePort < 65535
                    ? sourcePort + 1 : sourcePort - 1;
            int fallbackTcpSourcePort = intExtra(intent,
                    "b1FallbackTcpSourcePort", "fallbackTcpSourcePort",
                    fallbackDefaultPort);
            String payload = stringExtra(intent, "b1PayloadHex",
                    "payloadHex", "").replace(" ", "").replace(":", "");
            String error = "";
            if (family == null) {
                error = "family must be ip4 or ip6";
            } else if (protocol == null) {
                error = "protocol must be tcp or udp";
            } else if (!validPort(sourcePort) || !validPort(destinationPort)) {
                error = "source and destination ports must be 1..65535";
            } else if (timeout < 100 || timeout > 10000) {
                error = "timeoutMillis must be 100..10000";
                timeout = Math.max(100, Math.min(timeout, 10000));
            } else if (fallbackTcpOnTruncated && !"udp".equals(protocol)) {
                error = "fallbackTcpOnTruncated requires udp protocol";
            } else if (fallbackTcpOnTruncated && !dns) {
                error = "fallbackTcpOnTruncated requires DNS probe";
            } else if (fallbackTcpOnTruncated
                    && !validPort(fallbackTcpSourcePort)) {
                error = "fallback TCP source port must be 1..65535";
            } else if (payload.length() > 131070 || (payload.length() & 1) != 0) {
                error = "payloadHex must be even and at most 65535 bytes";
            } else if (dns && payload.isEmpty()) {
                error = "DNS probe requires payloadHex";
            } else if (!"separate".equals(tcpWriteMode)
                    && !"coalesced".equals(tcpWriteMode)) {
                error = "tcpWriteMode must be separate or coalesced";
            }
            return new B1Command(stage, family == null ? "" : family,
                    protocol == null ? "" : protocol, sourcePort,
                    stripIpv6Brackets(host), destinationPort, timeout, dns,
                    payload, tcpWriteMode, fallbackTcpOnTruncated,
                    fallbackTcpSourcePort, error);
        }

        B1Command tcpFallbackCommand() {
            return new B1Command(stageId, family, "tcp",
                    fallbackTcpSourcePort, destinationHost, destinationPort,
                    timeoutMillis, dns, payloadHex, tcpWriteMode, false,
                    fallbackTcpSourcePort, "");
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

        private static String defaultDestinationHost(String family) {
            return "ip6".equals(family)
                    ? "2606:4700:4700::1111" : "1.1.1.1";
        }
    }

    private static final class B1Result {
        final String bindResult;
        final long networkHandle;
        final String localAddress;
        final String destinationAddress;
        final String sendConnectOutcome;
        final String returnOutcome;
        final boolean tupleAttempted;
        final String error;
        final byte[] payload;
        final byte[] received;
        final boolean responseValid;
        final boolean udpTruncated;
        final boolean fallbackAttempted;
        final int fallbackSourcePort;
        final String fallbackReason;
        final String fallbackReturnOutcome;
        final int udpReceivedLength;
        final int tcpReceivedLength;
        final boolean tcpResponseValid;

        private B1Result(String bindResult, long networkHandle,
                         String localAddress, String destinationAddress,
                         String sendConnectOutcome, String returnOutcome,
                         boolean tupleAttempted, String error,
                         byte[] payload, byte[] received,
                         boolean responseValid, boolean udpTruncated,
                         boolean fallbackAttempted, int fallbackSourcePort,
                         String fallbackReason, String fallbackReturnOutcome,
                         int udpReceivedLength, int tcpReceivedLength,
                         boolean tcpResponseValid) {
            this.bindResult = bindResult;
            this.networkHandle = networkHandle;
            this.localAddress = localAddress == null ? "" : localAddress;
            this.destinationAddress = destinationAddress == null
                    ? "" : destinationAddress;
            this.sendConnectOutcome = sendConnectOutcome;
            this.returnOutcome = returnOutcome;
            this.tupleAttempted = tupleAttempted;
            this.error = error == null ? "" : error;
            this.payload = payload == null ? new byte[0] : payload;
            this.received = received == null ? new byte[0] : received;
            this.responseValid = responseValid;
            this.udpTruncated = udpTruncated;
            this.fallbackAttempted = fallbackAttempted;
            this.fallbackSourcePort = fallbackSourcePort;
            this.fallbackReason = fallbackReason == null ? "" : fallbackReason;
            this.fallbackReturnOutcome = fallbackReturnOutcome == null
                    ? "" : fallbackReturnOutcome;
            this.udpReceivedLength = udpReceivedLength;
            this.tcpReceivedLength = tcpReceivedLength;
            this.tcpResponseValid = tcpResponseValid;
        }

        int payloadLength() {
            return payload.length;
        }

        int receivedLength() {
            return received.length;
        }

        String payloadHex() {
            return toHex(payload);
        }

        String receivedPayloadHex() {
            return toHex(received);
        }

        boolean returnReceived() {
            return responseValid || "not_required".equals(returnOutcome);
        }

        static B1Result success(long handle, String bindResult, String local,
                                String destination, String sendOutcome,
                                String returnOutcome, boolean attempted,
                                String error, byte[] payload, byte[] received,
                                boolean valid) {
            return new B1Result(bindResult, handle, local, destination,
                    sendOutcome, returnOutcome, attempted, error, payload,
                    received, valid, false, false, 0, "", "", 0, 0, false);
        }

        static B1Result fallback(long handle, String bindResult, String local,
                                 String destination, String sendOutcome,
                                 String returnOutcome, boolean attempted,
                                 String error, byte[] payload, byte[] received,
                                 boolean valid, boolean udpTruncated,
                                 int fallbackSourcePort, String fallbackReason,
                                 String fallbackReturnOutcome,
                                 int udpReceivedLength, int tcpReceivedLength,
                                 boolean tcpResponseValid) {
            return new B1Result(bindResult, handle, local, destination,
                    sendOutcome, returnOutcome, attempted, error, payload,
                    received, valid, udpTruncated, true, fallbackSourcePort,
                    fallbackReason, fallbackReturnOutcome, udpReceivedLength,
                    tcpReceivedLength, tcpResponseValid);
        }

        static B1Result failure(long handle, String bindResult, String local,
                                String destination, String sendOutcome,
                                String returnOutcome, boolean attempted,
                                String error, byte[] payload, byte[] received,
                                boolean valid) {
            return success(handle, bindResult, local, destination, sendOutcome,
                    returnOutcome, attempted, error, payload, received, valid);
        }

        static B1Result unavailable(String destination, String error) {
            return failure(-1L, "unavailable", "", destination,
                    "vpn_unavailable", "not_attempted", false, error,
                    new byte[0], new byte[0], false);
        }

        static B1Result notAttempted(long handle, String destination,
                                     String outcome, String error) {
            return failure(handle, "not_attempted", "", destination, outcome,
                    "not_attempted", false, error, new byte[0], new byte[0],
                    false);
        }

        static B1Result invalid(String error, String destination) {
            return notAttempted(-1L, destination, "invalid_command", error);
        }
    }

    private static final class ProbeResult {
        final String bindResult;
        final long networkHandle;
        final String localAddress;
        final int localPort;
        final String destinationAddress;
        final String outcome;
        final boolean tupleAttempted;
        final String error;

        private ProbeResult(String bindResult, long networkHandle,
                            String localAddress, int localPort,
                            String destinationAddress, String outcome,
                            boolean tupleAttempted, String error) {
            this.bindResult = bindResult;
            this.networkHandle = networkHandle;
            this.localAddress = localAddress == null ? "" : localAddress;
            this.localPort = localPort;
            this.destinationAddress = destinationAddress == null
                    ? "" : destinationAddress;
            this.outcome = outcome;
            this.tupleAttempted = tupleAttempted;
            this.error = error == null ? "" : error;
        }

        static ProbeResult success(long handle, String bindResult, String local,
                                   String destination, String outcome,
                                   boolean attempted, String error) {
            return success(handle, bindResult, local, -1, destination,
                    outcome, attempted, error);
        }

        static ProbeResult success(long handle, String bindResult, String local,
                                   int localPort, String destination,
                                   String outcome, boolean attempted,
                                   String error) {
            return new ProbeResult(bindResult, handle, local, localPort,
                    destination, outcome, attempted, error);
        }

        static ProbeResult failure(long handle, String bindResult, String local,
                                   String destination, String outcome,
                                   boolean attempted, String error) {
            return failure(handle, bindResult, local, -1, destination,
                    outcome, attempted, error);
        }

        static ProbeResult failure(long handle, String bindResult, String local,
                                   int localPort, String destination,
                                   String outcome, boolean attempted,
                                   String error) {
            return new ProbeResult(bindResult, handle, local, localPort,
                    destination, outcome, attempted, error);
        }

        static ProbeResult unavailable(String destination, String error) {
            return new ProbeResult("unavailable", -1L, "", -1, destination,
                    "vpn_unavailable", false, error);
        }

        static ProbeResult notAttempted(long handle, String destination,
                                        String outcome, String error) {
            return new ProbeResult("not_attempted", handle, "", -1, destination,
                    outcome, false, error);
        }

        static ProbeResult invalid(String error, String destination) {
            return new ProbeResult("not_attempted", -1L, "", -1, destination,
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
